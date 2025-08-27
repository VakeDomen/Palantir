use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::{fs, thread};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, TimeZone};
use regex::Regex;
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind")]
enum Event {
    net(NetEvent),
    proc(ProcEvent),
}

#[derive(Serialize, Debug, Clone)]
struct ProcEvent {
    ts: String,
    user: String,
    pid: i32,
    comm: String,   // canonicalized name like "firefox"
    action: String, // "start" or "stop"
}

// keep NetEvent as before

#[derive(Serialize, Debug, Clone)]
struct NetEvent {
    ts: String,        // RFC3339 in local time
    src_ip: String,    // ip.src
    dns_qname: String, // dns.qry.name
}



lazy_static::lazy_static! {
    static ref RE_PS_LINE: Regex = Regex::new(
        r"^\s*(?P<pid>\d+)\s+(?P<ppid>\d+)\s+(?P<comm>\S*)\s*(?P<args>.*)$"
    ).unwrap();
}


fn fmt_rfc3339_local(epoch: f64) -> String {
    // epoch may have nanos after the decimal
    let secs = epoch.trunc() as i64;
    let nanos = (epoch.fract() * 1_000_000_000.0).round() as u32;
    Local.timestamp_opt(secs, nanos).single().unwrap().to_rfc3339()
}

fn now_local_rfc3339() -> String {
    Local::now().to_rfc3339()
}

fn spawn_tshark() -> std::io::Result<std::process::ChildStdout> {
    // Using frame.time_epoch so we control formatting
    let mut child = Command::new("tshark")
        .arg("-i").arg("any")
        .arg("-l")
        .arg("-q")
        .arg("-f").arg("udp port 53")
        .arg("-Y").arg("dns.flags.response==0")
        .arg("-T").arg("fields")
        .arg("-e").arg("frame.time_epoch")
        .arg("-e").arg("ip.src")
        .arg("-e").arg("dns.qry.name")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child.stdout.take().unwrap())
}

fn read_tshark() -> anyhow::Result<()> {
    let out = spawn_tshark()?;
    let mut br = BufReader::new(out);
    let mut line = String::new();

    while br.read_line(&mut line)? != 0 {
        let raw = line
            .trim()
            .to_string();
        
        line.clear();

        if raw.is_empty() { 
            continue; 
        }
        
        let parts: Vec<&str> = raw
            .split('\t')
            .collect();

        if parts.len() < 3 { 
            continue; 
        }

        let epoch: f64 = parts[0].parse().unwrap_or(0.0);
        let evt = Event::net(NetEvent {
            ts: fmt_rfc3339_local(epoch),
            src_ip: parts[1].to_string(),
            dns_qname: parts[2].to_string(),
        });
        println!("{}", serde_json::to_string(&evt)?);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PsRow {
    pid: i32,
    ppid: i32,
    comm: String,
    args: String, // used only for heuristics
}

fn ps_snapshot(user: &str, ignore_prefixes: &[&str]) -> anyhow::Result<std::collections::HashMap<i32, PsRow>> {
    let output = std::process::Command::new("ps")
        .arg("-u").arg(user)
        .arg("-o").arg("pid=")
        .arg("-o").arg("ppid=")
        .arg("-o").arg("comm=")
        .arg("-o").arg("args=")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = std::collections::HashMap::new();

    'lines: for line in stdout.lines() {
        if let Some(c) = RE_PS_LINE.captures(line) {
            let pid: i32 = c["pid"].parse().unwrap_or(-1);
            let ppid: i32 = c["ppid"].parse().unwrap_or(-1);
            let comm = c.name("comm").map(|m| m.as_str()).unwrap_or("").to_string();
            let args = c.name("args").map(|m| m.as_str()).unwrap_or("").to_string();

            for p in ignore_prefixes {
                if comm.starts_with(p) || args.starts_with(p) { continue 'lines; }
            }
            if pid > 0 {
                map.insert(pid, PsRow { pid, ppid, comm, args });
            }
        }
    }
    Ok(map)
}

fn exe_basename(pid: i32) -> Option<String> {
    let path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let base = path.file_name()?.to_string_lossy().to_string();
    let name = base.trim().to_lowercase();
    if name.is_empty() { None } else { Some(name) }
}

fn is_generic_child_name(name: &str) -> bool {
    let n = name.to_lowercase();
    // flexible contains-based checks to handle truncation
    n == "isolated"
        || n.contains("web content")
        || n.contains("renderer")
        || n.contains("gpu")
        || n.contains("utility")
        || n.contains("zygote")
        || n.contains("sandbox")
        || n.contains("content")
}

fn basename_from_args(args: &str) -> Option<String> {
    for tok in args.split_whitespace() {
        if let Some(i) = tok.rfind('/') {
            let base = &tok[i + 1..];
            if !base.is_empty() {
                let name = base.trim_end_matches(".bin").trim_end_matches(".exe").to_lowercase();
                if !name.is_empty() { return Some(name); }
            }
        }
    }
    None
}


fn canonical_name(pid: i32, curr: &std::collections::HashMap<i32, PsRow>) -> String {
    let mut depth = 0;
    let mut p = pid;
    // climb ancestors; prefer the real executable name
    while depth < 100 { 
        if let Some(row) = curr.get(&p) {
            if let Some(exe) = exe_basename(p) {
                if !is_generic_child_name(&exe) { return exe; }
            }
            if !row.comm.is_empty() && !is_generic_child_name(&row.comm) {
                return row.comm.to_lowercase();
            }
            if let Some(base) = basename_from_args(&row.args) {
                if !is_generic_child_name(&base) { return base; }
            }
            p = row.ppid;
            depth += 1;
            continue;
        }
        break;
    }
    // final fallback
    curr.get(&pid)
        .map(|r| if r.comm.is_empty() { "unknown".to_string() } else { r.comm.to_lowercase() })
        .unwrap_or_else(|| "unknown".to_string())
}


fn watch_processes(user: String, interval: Duration) -> anyhow::Result<()> {
    let ignore_prefixes = [
        "gnome-", "gsd-", "ibus-", "gvfs", "at-spi", "dbus", "xdg-", "systemd",
        "speech", "snapd", "wireplumber", "pipewire",
    ];

    // debounce and active state
    use std::collections::{HashMap, HashSet};
    let mut seen_once: HashSet<i32> = HashSet::new();

    // store canonical names for stops
    let mut active: HashMap<i32, String> = HashMap::new();

    loop {
        let curr = ps_snapshot(&user, &ignore_prefixes)?;

        // starts
        for pid in curr.keys() {
            if active.contains_key(pid) { continue; }
            if !seen_once.contains(pid) {
                seen_once.insert(*pid);
                continue;
            }
            let name = canonical_name(*pid, &curr);
            active.insert(*pid, name.clone());
            let evt = Event::proc(ProcEvent {
                ts: chrono::Local::now().to_rfc3339(),
                user: user.clone(),
                pid: *pid,
                comm: name,
                action: "start".to_string(),
            });
            println!("{}", serde_json::to_string(&evt)?);

        }

        // stops
        let curr_pids: std::collections::HashSet<i32> = curr.keys().cloned().collect();
        let gone: Vec<i32> = active.keys().filter(|pid| !curr_pids.contains(pid)).cloned().collect();
        for pid in gone {
            if let Some(name) = active.remove(&pid) {
                let evt = Event::proc(ProcEvent {
                    ts: chrono::Local::now().to_rfc3339(),
                    user: user.clone(),
                    pid,
                    comm: name,
                    action: "stop".to_string(),
                });
                println!("{}", serde_json::to_string(&evt)?);
            }
            seen_once.remove(&pid);
        }

        thread::sleep(interval);
    }
}

fn main() -> anyhow::Result<()> {
    let user = std::env::var("MONITOR_USER").unwrap_or_else(|_| "exam".to_string());
    let poll_millis: u64 = std::env::var("PAL_PS_INTERVAL_MILLIS").ok().and_then(|s| s.parse().ok()).unwrap_or(500);
    println!("MONITOR: {user}");


    let t_net = thread::spawn(move || {
        if let Err(e) = read_tshark() {
            eprintln!("tshark reader error: {e:?}");
        }
    });

    let user2 = user.clone();
    let t_proc = thread::spawn(move || {
        if let Err(e) = watch_processes(user2, Duration::from_millis(poll_millis)) {
            eprintln!("process watcher error: {e:?}");
        }
    });

    t_net.join().ok();
    t_proc.join().ok();
    Ok(())
}
