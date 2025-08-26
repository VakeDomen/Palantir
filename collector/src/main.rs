use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use lru::LruCache;
use dns_lookup::lookup_addr;

use dashmap::DashMap;
use get_if_addrs::get_if_addrs;
use lazy_static::lazy_static;
use log::{info, warn};
use procfs::net::{tcp, tcp6};
use procfs::process::FDTarget;
use regex::Regex;
use serde::Serialize;
use users::get_user_by_uid;

// -----------------------------------------------------------------------------
// Event model
// -----------------------------------------------------------------------------

#[derive(Serialize, Debug, Clone)]
struct NetEvent {
    ts: String,               // "2025-08-26 20:19:37.718228"
    proto: String,            // "tcp" | "udp"
    dir: String,              // "out" | "in" | "?"
    src: String,              // "ip:port" (local endpoint in our normalization)
    dst: String,              // "ip:port" (remote endpoint)
    dst_host: Option<String>, // reverse lookup via DNS capture
    len: Option<u32>,         // tcpdump reported length (if present)
    uid: Option<u32>,       // new
    user: Option<String>,   // new
    cmd: Option<String>,
}

// -----------------------------------------------------------------------------
// DNS cache + tracker
// -----------------------------------------------------------------------------

#[derive(Clone)]
struct DnsCache {
    // ip -> (host, expires_at)
    m: DashMap<IpAddr, (String, Instant)>,
    ttl: Duration,
}
impl DnsCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            m: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }
    fn put(&self, ip: IpAddr, host: String) {
        self.m.insert(ip, (host, Instant::now() + self.ttl));
    }
    fn get(&self, ip: &IpAddr) -> Option<String> {
        if let Some(entry) = self.m.get(ip) {
            if Instant::now() <= entry.value().1 {
                return Some(entry.value().0.clone());
            }
        }
        None
    }
    fn gc(&self) {
        let now = Instant::now();
        self.m.retain(|_, v| now <= v.1);
    }
}

#[derive(Clone)]
enum Pending {
    ForwardHost(String), // for A/AAAA/HTTPS
    ReverseIp(IpAddr),   // for PTR (reverse lookup)
}

#[derive(Clone)]
struct DnsTracker {
    q: DashMap<u16, (Pending, Instant)>,
    ttl: Duration,
}

impl DnsTracker {
    fn new(ttl_secs: u64) -> Self {
        Self { q: DashMap::new(), ttl: Duration::from_secs(ttl_secs) }
    }
    fn put_forward(&self, id: u16, host: String) {
        self.q.insert(id, (Pending::ForwardHost(host), Instant::now() + self.ttl));
    }
    fn put_reverse(&self, id: u16, ip: IpAddr) {
        self.q.insert(id, (Pending::ReverseIp(ip), Instant::now() + self.ttl));
    }
    fn take(&self, id: u16) -> Option<Pending> {
        self.q.remove(&id).map(|(_, v)| v.0)
    }
    fn gc(&self) {
        let now = Instant::now();
        self.q.retain(|_, v| now <= v.1);
    }
}


#[derive(Clone)]
struct DnsAlias {
    m: DashMap<String, (String, Instant)>, // alias -> (canonical, expires)
    ttl: Duration,
}
impl DnsAlias {
    fn new(ttl_secs: u64) -> Self {
        Self { m: DashMap::new(), ttl: Duration::from_secs(ttl_secs) }
    }
    fn put(&self, alias: String, canonical: String) {
        self.m.insert(alias, (canonical, Instant::now() + self.ttl));
    }
    fn resolve(&self, name: &str) -> String {
        // follow at most one hop; good enough for telemetry attribution
        if let Some(v) = self.m.get(name) {
            if Instant::now() <= v.1 { return v.0.clone(); }
        }
        name.to_string()
    }
    fn gc(&self) {
        let now = Instant::now();
        self.m.retain(|_, v| now <= v.1);
    }
}

#[derive(Clone)]
struct ReverseResolver {
    cache: Arc<Mutex<LruCache<IpAddr, Option<String>>>>,
    timeout: Duration,
}
impl ReverseResolver {
    fn new(capacity: usize, timeout_ms: u64) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap()))),
            timeout: Duration::from_millis(timeout_ms),
        }
    }
    fn lookup(&self, ip: IpAddr) -> Option<String> {
        // quick cache hit
        if let Some(v) = self.cache.lock().unwrap().get(&ip).cloned() {
            return v;
        }
        // do a bounded-time PTR in a helper thread
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let ip_copy = ip;
        thread::spawn(move || {
            let res = lookup_addr(&ip_copy).ok();
            // normalize: strip trailing dot if any
            let res = res.map(|mut s| { if s.ends_with('.') { s.pop(); } s });
            let _ = tx.send(res);
        });
        let res = rx.recv_timeout(self.timeout).ok().flatten();
        // memoize (even None to avoid repeated lookups)
        self.cache.lock().unwrap().put(ip, res.clone());
        res
    }
}

// -----------------------------------------------------------------------------
// Regexes for parsing tcpdump output
// -----------------------------------------------------------------------------

lazy_static! {
    // Two-line IPv4 form:
    //   2025-08-26 ... IP (....)
    //       10.252.67.116.56894 > 3.120.51.72.443: Flags ... length 0
    static ref RE_DATA_V4_TWOLINE: Regex = Regex::new(
        r#"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}).*\n\s*(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\.(?P<srcport>\d+)\s*>\s*(?P<dstip>\d{1,3}(?:\.\d{1,3}){3})\.(?P<dstport>\d+):.*?(?:length\s+(?P<len>\d+))?"#
    ).unwrap();

    // Two-line IPv6 form:
    static ref RE_DATA_V6_TWOLINE: Regex = Regex::new(
        r#"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}).*\n\s*(?P<srcip>[0-9a-fA-F:]+)\.(?P<srcport>\d+)\s*>\s*(?P<dstip>[0-9a-fA-F:]+)\.(?P<dstport>\d+):.*?(?:length\s+(?P<len>\d+))?"#
    ).unwrap();

    // Single-line fallback (some tcpdump builds print everything in one line):
    static ref RE_DATA_SINGLE: Regex = Regex::new(
        r#"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}).*\s+(?P<srcip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+))\.(?P<srcport>\d+)\s*>\s*(?P<dstip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+))\.(?P<dstport>\d+):.*?(?:length\s+(?P<len>\d+))?"#
    ).unwrap();

    // DNS query:
    //   ... : 38377+ A? global.quickconnect.to. (40)
    static ref RE_DNS_Q: Regex = Regex::new(
        r#":\s+(?P<id>\d+)\+\s+(?P<rtype>A|AAAA|HTTPS|PTR)\?\s+(?P<host>[A-Za-z0-9\.\-]+)\."#
    ).unwrap();

    static ref RE_DNS_PTR_ANS: Regex = Regex::new(
        r#"(?:^|[\s,])PTR\s+(?P<ptr>[A-Za-z0-9\.\-]+)\."#
    ).unwrap();

    // DNS answer head:
    //   ... : 27362 4/0/0 A 65.9.189.13, A 65.9.189.99 ...
    static ref RE_DNS_ANS_HEAD: Regex = Regex::new(
        r#":\s+(?P<id>\d+)\s+\d+/\d+/\d+\s+"#
    ).unwrap();

    // Extract A/AAAA values from answer line (supports mixed A/AAAA lists)
    static ref RE_DNS_IPS: Regex = Regex::new(
        r#"(?:^|[\s,])A\s+(?P<a>\d{1,3}(?:\.\d{1,3}){3})|AAAA\s+(?P<aaaa>[0-9a-fA-F:]+)"#
    ).unwrap();

    // e.g. "CNAME onedscolprdweu09.westeurope.cloudapp.azure.com."
    static ref RE_DNS_CNAME: Regex = Regex::new(
        r#"CNAME\s+(?P<cname>[A-Za-z0-9\.\-]+)\."#
    ).unwrap();

    // A / AAAA answers
    static ref RE_DNS_AAAA: Regex = Regex::new(
        r#"(?:^|[\s,])A\s+(?P<a>[\d\.]+)|AAAA\s+(?P<aaaa>[0-9a-fA-F:]+)"#
    ).unwrap();
}

// -----------------------------------------------------------------------------
// Local IPs / helpers
// -----------------------------------------------------------------------------


fn build_socket_map() -> HashMap<u64, (i32, u32, String)> {
    let mut map = HashMap::new();

    // Collect all processes
    if let Ok(all) = procfs::process::all_processes() {
        for pr in all.flatten() {
            let uid = pr.uid().unwrap_or(0);
            let cmd = pr.cmdline().unwrap_or_default().join(" ");
            if let Ok(fds) = pr.fd() {
                for fd in fds.flatten() {
                    if let FDTarget::Socket(inode) = fd.target {
                        map.insert(inode, (pr.pid, uid, cmd.clone()));
                    }
                }
            }
        }
    }
    map
}

fn find_inode(sa: &SocketAddr) -> Option<u64> {
    // Try IPv4 first
    if sa.is_ipv4() {
        if let Ok(t) = tcp() {
            for e in t {
                if e.local_address == *sa {
                    return Some(e.inode);
                }
            }
        }
    } else {
        if let Ok(t) = tcp6() {
            for e in t {
                if e.local_address == *sa {
                    return Some(e.inode);
                }
            }
        }
    }
    None
}


fn local_ips() -> Vec<IpAddr> {
    let mut v = Vec::new();
    if let Ok(ifaces) = get_if_addrs() {
        for iface in ifaces {
            if !iface.is_loopback() {
                v.push(iface.ip());
            }
        }
    }
    v
}

fn is_local(ip: &IpAddr, locals: &[IpAddr]) -> bool {
    locals.iter().any(|x| x == ip)
}

// -----------------------------------------------------------------------------
// Spawn tcpdump
// -----------------------------------------------------------------------------
fn spawn_tcpdump_data(iface: &str) -> std::io::Result<std::process::ChildStdout> {
    // Only TCP with SYN/FIN/RST/PSH (no pure ACKs) + all UDP.
    let filter = concat!(
        "(ip or ip6) and (",
          "udp or (tcp and (tcp[13] & 0x17 != 0))",
        ") ",
        "and not port 53 and not port 5353 and not port 67 and not port 68 and not port 123 ",
        "and not (net 127.0.0.0/8 or ip6 host ::1) ",
        "and not multicast"
    );

    let mut child = std::process::Command::new("tcpdump")
        .arg("-i").arg(iface)
        .arg("-nn")         // no name/port resolution
        .arg("-tttt")       // full timestamp (you parse this)
        .arg("-l")          // line-buffered
        .arg("-q")          // quieter (single-line, fewer extras)
        .arg("-s").arg("0") // snaplen: full packet (for length field)
        .arg(filter)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    Ok(child.stdout.take().unwrap())
}


fn spawn_tcpdump_dns(iface: &str) -> std::io::Result<std::process::ChildStdout> {
    let mut child = Command::new("tcpdump")
        .arg("-i")
        .arg(iface)
        .arg("-nn")
        .arg("-tttt")
        .arg("-l")
        .arg("-s")
        .arg("0")
        .arg("port 53 and (udp or tcp)")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child.stdout.take().unwrap())
}

// -----------------------------------------------------------------------------
// Parsers
// -----------------------------------------------------------------------------

fn parse_data_block(block: &str) -> Option<(String, SocketAddr, SocketAddr, Option<u32>)> {
    if let Some(c) = RE_DATA_V4_TWOLINE.captures(block) {
        let ts = c["ts"].to_string();
        let src: SocketAddr = format!("{}:{}", &c["srcip"], &c["srcport"]).parse().ok()?;
        let dst: SocketAddr = format!("{}:{}", &c["dstip"], &c["dstport"]).parse().ok()?;
        let len = c.name("len").and_then(|m| m.as_str().parse::<u32>().ok());
        return Some((ts, src, dst, len));
    }
    if let Some(c) = RE_DATA_V6_TWOLINE.captures(block) {
        let ts = c["ts"].to_string();
        let src: SocketAddr = format!("{}:{}", &c["srcip"], &c["srcport"]).parse().ok()?;
        let dst: SocketAddr = format!("{}:{}", &c["dstip"], &c["dstport"]).parse().ok()?;
        let len = c.name("len").and_then(|m| m.as_str().parse::<u32>().ok());
        return Some((ts, src, dst, len));
    }
    if let Some(c) = RE_DATA_SINGLE.captures(block) {
        let ts = c["ts"].to_string();
        let src: SocketAddr = format!("{}:{}", &c["srcip"], &c["srcport"]).parse().ok()?;
        let dst: SocketAddr = format!("{}:{}", &c["dstip"], &c["dstport"]).parse().ok()?;
        let len = c.name("len").and_then(|m| m.as_str().parse::<u32>().ok());
        return Some((ts, src, dst, len));
    }
    None
}

fn resolve_host(
    ip: &IpAddr,
    cache: &DnsCache,
    alias: &DnsAlias,
    rdns: &ReverseResolver,
) -> Option<String> {
    // 1) passive cache from live DNS
    if let Some(h) = cache.get(ip) {
        return Some(alias.resolve(&h));
    }
    // 2) fast reverse PTR (75ms timeout, cached)
    rdns.lookup(*ip).map(|h| alias.resolve(&h))
}


// -----------------------------------------------------------------------------
// Readers
// -----------------------------------------------------------------------------

fn read_data(
    name: &str,
    reader: impl std::io::Read,
    locals: Vec<IpAddr>,
    cache: DnsCache,
    alias: DnsAlias,
    rdns: ReverseResolver,  
) -> anyhow::Result<()> {
    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let mut prev = String::new();
    let mut last_gc = Instant::now();
    let mut last_sockmap = Instant::now();

    let mut socket_map = build_socket_map();

    loop {

        socket_map = build_socket_map();


        buf.clear();
        let n = br.read_line(&mut buf)?;
        if n == 0 {
            break;
        }

        // block mode: tcpdump often emits 2 lines per packet
        if prev.is_empty() {
            prev.push_str(&buf);
            continue;
        }
        let block = format!("{}{}", prev, buf);

        // attempt parse
        let parsed = parse_data_block(&block).or_else(|| parse_data_block(&buf));
        prev.clear();

        if let Some((ts, src, dst, len)) = parsed {
            // direction detection
            let (dir, me, peer) = if is_local(&src.ip(), &locals) && !is_local(&dst.ip(), &locals) {
                ("out", src, dst)
            } else if is_local(&dst.ip(), &locals) && !is_local(&src.ip(), &locals) {
                ("in", dst, src)
            } else {
                ("?", src, dst)
            };

            // we only care about outgoing
            if dir != "out" {
                continue;
            }

            // skip localhost
            if me.ip().is_loopback() || peer.ip().is_loopback() {
                continue;
            }

            // refresh socket map every 5s
            // if last_sockmap.elapsed() > Duration::from_millis(100) {
                // last_sockmap = Instant::now();
            // }

            let mut uid = None;
            let mut user = None;
            let mut cmd = None;

            if let Some(inode) = find_inode(&me) {
                if let Some((_, u, c)) = socket_map.get(&inode) {
                    if *u == 0 {
                        // skip root/system
                        continue;
                    }
                    uid = Some(*u);
                    user = get_user_by_uid(*u)
                        .map(|u| u
                            .name()
                            .to_string_lossy()
                            .into_owned()
                        );
                    cmd = Some(
                        c
                            .split(" ")
                            .nth(0)
                            .unwrap_or_default()
                            .into()
                    );
                }
            }

            let host = resolve_host(&peer.ip(), &cache, &alias, &rdns);

            if user.is_none() {
                continue;
            }
            let evt = NetEvent {
                ts,
                proto: "tcp".into(),
                dir: dir.into(),
                src: me.to_string(),
                dst: peer.to_string(),
                dst_host: host,
                len,
                uid,
                user,
                cmd,
            };

            println!("{}", serde_json::to_string(&evt)?);
        }

        // periodic cleanup
        if last_gc.elapsed() > Duration::from_secs(30) {
            cache.gc();
            last_gc = Instant::now();
        }
    }

    Ok(())
}

fn read_dns(name: &str,
    reader: impl std::io::Read,
    cache: DnsCache,
    tracker: DnsTracker,
    alias: DnsAlias,
) -> anyhow::Result<()> {
    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let mut last_gc = Instant::now();

    loop {
        buf.clear();
        let n = br.read_line(&mut buf)?;
        if n == 0 {
            break;
        }

        let line = buf.trim_end();

        // Record queries (ID -> host)
        if let Some(c) = RE_DNS_Q.captures(line) {
            let id: u16 = c["id"].parse().unwrap_or(0);
            let rtype = &c["rtype"];
            let host = c["host"].to_string();

            match rtype {
                "PTR" => {
                    if let Some(ip) = parse_ptr_qname_to_ip(&format!("{}.", host)) {
                        tracker.put_reverse(id, ip);
                    }
                }
                _ => {
                    // forward: A/AAAA/HTTPS — we’ll cache ip -> host on the answer
                    tracker.put_forward(id, host);
                }
            }
            info!("{name}: {line}");
            continue;
        }


        // For answers, get ID then extract CNAME/A/AAAA
        if let Some(h) = RE_DNS_ANS_HEAD.captures(line) {
        let id: u16 = h["id"].parse().unwrap_or(0);
        if let Some(pending) = tracker.take(id) {
            match pending {
                Pending::ForwardHost(host) => {
                    // 3a) Record any CNAMEs present: map each alias to the last name in the chain
                    let mut last = host.clone();
                    // Collect all CNAMEs in order they appear
                    let mut cnames: Vec<String> = RE_DNS_CNAME
                        .captures_iter(line)
                        .filter_map(|m| m.name("cname").map(|x| x.as_str().to_string()))
                        .collect();

                    if !cnames.is_empty() {
                        // The ultimate canonical is the last CNAME seen
                        let canonical = cnames.last().unwrap().clone();
                        // Map the query host and each intermediate alias to canonical
                        alias.put(host.clone(), canonical.clone());
                        for a in cnames.drain(..) {
                            alias.put(a, canonical.clone());
                        }
                        last = canonical;
                    }

                    // 3b) Cache A/AAAA → host (canonical if we found one)
                    for m in RE_DNS_AAAA.captures_iter(line) {
                        if let Some(a) = m.name("a") {
                            if let Ok(ip) = a.as_str().parse::<IpAddr>() {
                                cache.put(ip, last.clone());
                            }
                        }
                        if let Some(aaaa) = m.name("aaaa") {
                            if let Ok(ip) = aaaa.as_str().parse::<IpAddr>() {
                                cache.put(ip, last.clone());
                            }
                        }
                    }
                }

                Pending::ReverseIp(ip) => {
                    // take the first PTR target and cache ip -> ptr-name
                    if let Some(m) = RE_DNS_PTR_ANS.captures(line) {
                        let ptr = m.name("ptr").map(|x| x.as_str().to_string());
                        if let Some(ptr_host) = ptr {
                            cache.put(ip, ptr_host);
                        }
                    }
                }
            }
        }
        info!("{name}: {line}");
    } else {
        info!("{name}: {line}");
    }



        if last_gc.elapsed() > Duration::from_secs(30) {
            cache.gc();
            tracker.gc();
            alias.gc();
            last_gc = Instant::now();
        }

    }

    Ok(())
}

fn is_localhost(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn parse_ptr_qname_to_ip(qname: &str) -> Option<IpAddr> {
    if let Some(rest) = qname.strip_suffix(".in-addr.arpa") {
        // IPv4: a.b.c.d.in-addr.arpa (reversed)
        let parts: Vec<&str> = rest.trim_end_matches('.').split('.').collect();
        if parts.len() == 4 {
            let octets = [parts[3], parts[2], parts[1], parts[0]];
            let s = octets.join(".");
            return s.parse::<std::net::Ipv4Addr>().map(IpAddr::V4).ok();
        }
    } else if let Some(rest) = qname.strip_suffix(".ip6.arpa") {
        // IPv6 nibble-reversed (hex nibbles separated by dots)
        let nibbles: Vec<&str> = rest.trim_end_matches('.').split('.').collect();
        if !nibbles.is_empty() {
            let mut hex = String::new();
            for ch in nibbles.iter().rev() {
                hex.push_str(ch);
            }
            // insert colons every 4 hex chars
            let mut groups = Vec::new();
            for chunk in hex.as_bytes().chunks(4) {
                groups.push(std::str::from_utf8(chunk).ok()?.to_string());
            }
            let addr = groups.join(":");
            return addr.parse::<std::net::Ipv6Addr>().map(IpAddr::V6).ok();
        }
    }
    None
}


// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

fn pick_iface() -> String {
    if let Ok(v) = std::env::var("PAL_IFACE") {
        return v;
    }
    // fallback: first non-loopback device
    if let Ok(list) = pcap::Device::list() {
        for d in list {
            if d.name != "lo" {
                return d.name;
            }
        }
    }
    "lo".into()
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    info!("starting palantir-collector");

    let iface = pick_iface();
    info!("capturing on interface: {}", &iface);

    let locals = local_ips();

    // shared state
    let cache   = DnsCache::new(300);  // 5 min
    let tracker = DnsTracker::new(120); // 2 min
    let alias   = DnsAlias::new(300);  // 5 min
    let rdns    = ReverseResolver::new(256, 75); // 256 entries, 75ms timeout per PTR

    let data_out = spawn_tcpdump_data(&iface)?;
    let dns_out  = spawn_tcpdump_dns(&iface)?;

    // DATA
    let cache_d   = cache.clone();
    let alias_d   = alias.clone();
    let rdns_d    = rdns.clone();
    let locals_d  = locals.clone();
    let t1 = std::thread::spawn(move || {
        if let Err(e) = read_data("DATA", data_out, locals_d, cache_d, alias_d, rdns_d) {
            warn!("DATA reader error: {e:?}");
        }
    });

    // DNS
    let cache_n   = cache.clone();
    let tracker_n = tracker.clone();
    let alias_n   = alias.clone();
    let t2 = std::thread::spawn(move || {
        if let Err(e) = read_dns("DNS", dns_out, cache_n, tracker_n, alias_n) {
            warn!("DNS reader error: {e:?}");
        }
    });

    t1.join().ok();
    t2.join().ok();

    Ok(())
}
