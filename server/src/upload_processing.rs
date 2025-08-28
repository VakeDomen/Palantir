use std::{collections::{HashMap, HashSet}, fs, path::PathBuf};

use actix_web::web;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;
use zip::ZipArchive;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime, UtcOffset};

use crate::AppState;


struct Finding {
    kind: String,     // proc, net, meta, anomaly
    key: String,      // e.g. total_proc_starts, top_domain, first_ts
    value: String,    // stringified value
    severity: String, // info, warn, critical
}
struct AnalysisResult {
    findings: Vec<Finding>,
    now_rfc3339: String,
}

fn ai_provider_list() -> &'static [&'static str] {
    &[
        "openai.com","chatgpt.com",
        "anthropic.com","claude.ai",
        "ai.google","deepmind.com","google.com",
        "microsoft.com","azure.com",
        "mistral.ai","cohere.ai","stability.ai",
        "ai21.com","perplexity.ai",
        "huggingface.co","replicate.com","runpod.io",
        "openrouter.ai","poe.com",
        "x.ai","you.com","character.ai",
        "elevenlabs.io","jasper.ai","writesonic.com","copy.ai","rytr.me",
    ]
}

fn base_domain_guess(host: &str) -> String {
    let mut parts: Vec<&str> = host
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() >= 2 {
        let last = parts.pop().unwrap();
        let prev = parts.pop().unwrap();
        format!("{prev}.{last}")
    } else {
        host.to_ascii_lowercase()
    }
}

fn is_browser(comm: &str) -> bool {
    let c = comm.to_ascii_lowercase();
    ["firefox","chrome","chromium","brave","edge","opera"].iter().any(|b| c.contains(b))
}
fn is_shell(comm: &str) -> bool {
    let c = comm.to_ascii_lowercase();
    ["bash","zsh","fish","sh","dash"].iter().any(|b| c==*b || c.ends_with(format!("/{b}").as_str()))
}
fn is_remote_tool(comm: &str) -> bool {
    let c = comm.to_ascii_lowercase();
    ["anydesk","teamviewer","rustdesk","remmina","x11vnc","vino","vnc",
     "zoom","teams","discord","slack"].iter().any(|b| c.contains(b))
}
fn is_ssh_like(comm: &str) -> bool {
    let c = comm.to_ascii_lowercase();
    ["ssh","scp","sftp","mosh"].iter().any(|b| c==*b || c.starts_with(&format!("{b} ")))
}
fn is_download_tool(comm: &str) -> bool {
    let c = comm.to_ascii_lowercase();
    ["curl","wget","pip","pip3","conda","npm","pnpm","yarn","apt","dnf","pacman"]
        .iter().any(|b| c==*b || c.starts_with(&format!("{b} ")))
}

fn is_private_ipv4(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.20.")
        || ip.starts_with("172.21.")
        || ip.starts_with("172.22.")
        || ip.starts_with("172.23.")
        || ip.starts_with("172.24.")
        || ip.starts_with("172.25.")
        || ip.starts_with("172.26.")
        || ip.starts_with("172.27.")
        || ip.starts_with("172.28.")
        || ip.starts_with("172.29.")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
}

pub fn pretty_rfc3339(s: &str) -> String {
    let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) else { return s.to_string(); };
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let local = dt.to_offset(offset);
    let fmt = time::format_description::parse("[month repr:short] [day], [year] [hour]:[minute]").unwrap();
    local.format(&fmt).unwrap_or_else(|_| s.to_string())
}

pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}


fn ai_provider_suffixes() -> &'static [&'static str] {
    &[
        "openai.com","chatgpt.com",
        "anthropic.com","claude.ai",
        "ai.google","deepmind.com","google.com",   // gemini.google.com etc
        "microsoft.com","azure.com",               // copilot, azure openai
        "mistral.ai","cohere.ai","stability.ai",
        "ai21.com","perplexity.ai",
        "huggingface.co","replicate.com","runpod.io",
        "openrouter.ai","poe.com",
        "x.ai","you.com","character.ai",
        "elevenlabs.io","jasper.ai","writesonic.com","copy.ai","rytr.me",
    ]
}


fn analyze_zip(zip_path: PathBuf) -> Result<AnalysisResult, String> {
    use std::io::Read;
    let mut zip_file = std::fs::File::open(&zip_path)
        .map_err(|e| format!("open zip {}: {e}", zip_path.display()))?;
    let mut archive = ZipArchive::new(&mut zip_file)
        .map_err(|e| format!("read zip {}: {e}", zip_path.display()))?;

    // optional manifest
    let mut _manifest_json = String::new();
    if let Ok(mut f) = archive.by_name("manifest.json") {
        f.read_to_string(&mut _manifest_json).map_err(|e| e.to_string())?;
    }

    // log
    let mut log_buf = String::new();
    if let Ok(mut f) = archive.by_name("snapshot/palantir.log") {
        f.read_to_string(&mut log_buf).map_err(|e| e.to_string())?;
    } else {
        return Err("missing snapshot/palantir.log".to_string());
    }

    // timebook
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;
    let mut ts_prev: Option<OffsetDateTime> = None;
    let mut max_idle: i64 = 0; // seconds
    let mut event_ts: Vec<OffsetDateTime> = Vec::new();

    // proc trackers
    let mut proc_starts = 0;
    let mut proc_stops  = 0;
    let mut procs: HashMap<String, usize> = HashMap::new();
    let mut had_browser = false;
    let mut browser_runtime_sec: i64 = 0;
    let mut shell_count = 0;
    let mut remote_flag = false;
    let mut ssh_flag = false;
    let mut download_tool_count = 0;

    let mut pid_start: HashMap<i64, (String, OffsetDateTime)> = HashMap::new();
    let mut comm_runtime: HashMap<String, i64> = HashMap::new();
    let mut orphaned: HashSet<i64> = HashSet::new();
    let mut browser_intervals: Vec<(OffsetDateTime, OffsetDateTime)> = Vec::new();
    let mut shell_intervals: Vec<(OffsetDateTime, OffsetDateTime)> = Vec::new();

    // net trackers
    let mut total_net_events: usize = 0;
    let mut domains: HashMap<String, usize> = HashMap::new();
    let mut src_ips: HashMap<String, usize> = HashMap::new();
    let mut ai_hits_total = 0usize;
    let mut ai_domains: HashMap<String, usize> = HashMap::new();

    // categories
    let mut qna_hits = 0usize;
    let mut code_host_hits = 0usize;
    let mut search_hits = 0usize;
    let mut pkg_hits = 0usize;
    let mut cloud_hits = 0usize;

    for line in log_buf.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => continue };
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let ts_s = v.get("ts").and_then(|x| x.as_str()).unwrap_or("").to_string();

        if !ts_s.is_empty() {
            if first_ts.is_none() { first_ts = Some(ts_s.clone()); }
            last_ts = Some(ts_s.clone());

            if let Some(curr) = parse_rfc3339(&ts_s) {
                if let Some(prev) = ts_prev {
                    let gap = (curr - prev).whole_seconds();
                    if gap > max_idle { max_idle = gap; }
                }
                ts_prev = Some(curr);
                event_ts.push(curr);
            }
        }

        match kind {
            "proc" => {
                let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
                let comm = v.get("comm").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
                let pid  = v.get("pid").and_then(|x| x.as_i64()).unwrap_or(-1);

                if action == "start" {
                    proc_starts += 1;
                    *procs.entry(comm.clone()).or_default() += 1;
                    if is_browser(&comm) { had_browser = true; }
                    if is_shell(&comm) { shell_count += 1; }
                    if is_remote_tool(&comm) { remote_flag = true; }
                    if is_ssh_like(&comm) { ssh_flag = true; }
                    if is_download_tool(&comm) { download_tool_count += 1; }
                    if let Some(t) = parse_rfc3339(&ts_s) {
                        pid_start.insert(pid, (comm.clone(), t));
                        orphaned.insert(pid);
                    }
                } else if action == "stop" {
                    proc_stops += 1;
                    orphaned.remove(&pid);
                    if let Some((c0, t0)) = pid_start.remove(&pid) {
                        if let Some(t1) = parse_rfc3339(&ts_s) {
                            let secs = (t1 - t0).whole_seconds().max(0);
                            *comm_runtime.entry(c0.clone()).or_default() += secs;
                            if is_browser(&c0) { browser_runtime_sec += secs; }
                            if is_shell(&c0) { shell_intervals.push((t0, t1)); }
                            if is_browser(&c0) { browser_intervals.push((t0, t1)); }
                        }
                    }
                }
            }
            "net" => {
                total_net_events += 1;
                if let Some(d) = v.get("dns_qname").and_then(|x| x.as_str()) {
                    let host = d.to_string();
                    *domains.entry(host.clone()).or_default() += 1;

                    let base = base_domain_guess(&host);
                    if ai_provider_list().iter().any(|s| base == *s) {
                        ai_hits_total += 1;
                        *ai_domains.entry(base.clone()).or_default() += 1;
                    }
                    // categories
                    if ["google.com","bing.com","duckduckgo.com"].iter().any(|s| base == *s) { search_hits += 1; }
                    if ["stackoverflow.com","stackexchange.com"].iter().any(|s| base == *s) { qna_hits += 1; }
                    if ["github.com","gitlab.com","bitbucket.org"].iter().any(|s| base == *s) { code_host_hits += 1; }
                    if ["pypi.org","pythonhosted.org","npmjs.com","registry.npmjs.org","crates.io"].iter().any(|s| base == *s) { pkg_hits += 1; }
                    if ["drive.google.com","dropbox.com","mega.nz","wetransfer.com","pastebin.com","hastebin.com","ghostbin.com"].iter().any(|s| base == *s) { cloud_hits += 1; }
                }
                if let Some(ip) = v.get("src_ip").and_then(|x| x.as_str()) {
                    *src_ips.entry(ip.to_string()).or_default() += 1;
                }
            }
            _ => {}
        }
    }

    // helpers
    fn top_k(map: &HashMap<String, usize>, k: usize) -> Vec<(String, usize)> {
        let mut v: Vec<_> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(k);
        v
    }
    fn overlaps(a: &(OffsetDateTime, OffsetDateTime), b: &(OffsetDateTime, OffsetDateTime)) -> bool {
        a.0 <= b.1 && b.0 <= a.1
    }

    // intensity
    let burst_max_per_min = if event_ts.is_empty() {
        0
    } else {
        let mut by_min: HashMap<i64, i64> = HashMap::new();
        for t in &event_ts {
            let m = t.unix_timestamp() / 60;
            *by_min.entry(m).or_default() += 1;
        }
        *by_min.values().max().unwrap_or(&0)
    };
    let final5_net_events = if let (Some(a), Some(b)) = (first_ts.as_deref().and_then(parse_rfc3339), last_ts.as_deref().and_then(parse_rfc3339)) {
        let cutoff = b - time::Duration::minutes(5);
        event_ts.iter().filter(|t| **t >= cutoff && **t <= b).count() as i64
    } else { 0 };

    // top runtime
    let top_runtime = comm_runtime.iter().max_by_key(|(_, s)| *s).map(|(c, s)| (c.clone(), *s)).unwrap_or(("".into(), 0));
    let shell_and_browser_overlap = shell_intervals.iter().any(|s| browser_intervals.iter().any(|b| overlaps(s, b)));

    // choose a seat IP from private IPs with highest count
    let seat_ip_opt = src_ips.iter()
        .filter(|(ip, _)| is_private_ipv4(ip))
        .max_by_key(|(_, c)| **c)
        .map(|(ip, _)| ip.clone());

    // build findings
    let mut findings = Vec::new();
    let now_rfc3339 = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "now".to_string());

    findings.push(Finding{ kind: "meta".into(), key: "zip_name".into(), value: zip_path.file_name().unwrap_or_default().to_string_lossy().to_string(), severity: "info".into() });
    if let Some(ts) = &first_ts { findings.push(Finding{ kind: "meta".into(), key: "first_ts".into(), value: ts.clone(), severity: "info".into() }); }
    if let Some(ts) = &last_ts  { findings.push(Finding{ kind: "meta".into(), key: "last_ts".into(),  value: ts.clone(), severity: "info".into() }); }

    if let (Some(a), Some(b)) = (first_ts.as_deref().and_then(parse_rfc3339), last_ts.as_deref().and_then(parse_rfc3339)) {
        let mins = (b - a).whole_minutes().max(0);
        findings.push(Finding{ kind: "meta".into(), key: "duration_minutes".into(), value: mins.to_string(), severity: "info".into() });
        if mins > 0 {
            let rpm = (total_net_events as i64) / mins.max(1);
            findings.push(Finding{ kind: "net".into(), key: "requests_per_min".into(), value: rpm.to_string(), severity: "info".into() });
        }
    }

    findings.push(Finding{ kind: "meta".into(), key: "max_idle_seconds".into(), value: max_idle.to_string(), severity: if max_idle >= 300 { "warn".into() } else { "info".into() } });

    findings.push(Finding{ kind: "proc".into(), key: "total_proc_starts".into(), value: proc_starts.to_string(), severity: "info".into() });
    findings.push(Finding{ kind: "proc".into(), key: "total_proc_stops".into(),  value: proc_stops.to_string(),  severity: "info".into() });
    for (comm, cnt) in top_k(&procs, 10) {
        findings.push(Finding{ kind: "proc".into(), key: "top_proc".into(), value: format!("{comm}:{cnt}"), severity: "info".into() });
    }
    if browser_runtime_sec > 0 {
        findings.push(Finding{ kind: "proc".into(), key: "browser_runtime_seconds".into(), value: browser_runtime_sec.to_string(), severity: "info".into() });
    }
    findings.push(Finding{ kind: "proc".into(), key: "had_browser".into(), value: had_browser.to_string(), severity: if had_browser { "warn".into() } else { "info".into() } });

    if shell_count > 0 {
        findings.push(Finding{ kind: "proc".into(), key: "shell_invocations".into(), value: shell_count.to_string(), severity: "info".into() });
    }
    if download_tool_count > 0 {
        findings.push(Finding{ kind: "proc".into(), key: "external_download_tool_count".into(), value: download_tool_count.to_string(), severity: "warn".into() });
    }
    if remote_flag {
        findings.push(Finding{ kind: "anomaly".into(), key: "remote_collab_tool_seen".into(), value: "true".into(), severity: "critical".into() });
    }
    if ssh_flag {
        findings.push(Finding{ kind: "anomaly".into(), key: "ssh_activity".into(), value: "true".into(), severity: "warn".into() });
    }

    findings.push(Finding{ kind: "net".into(), key: "total_net_events".into(), value: total_net_events.to_string(), severity: "info".into() });
    findings.push(Finding{ kind: "net".into(), key: "unique_domains".into(), value: domains.len().to_string(), severity: "info".into() });
    for (d, cnt) in top_k(&domains, 10) {
        findings.push(Finding{ kind: "net".into(), key: "top_domain".into(), value: format!("{d}:{cnt}"), severity: "info".into() });
    }

    for (ip, cnt) in top_k(&src_ips, 5) {
        findings.push(Finding{ kind: "net".into(), key: "top_src_ip".into(), value: format!("{ip}:{cnt}"), severity: "info".into() });
    }
    if let Some(seat_ip) = seat_ip_opt {
        findings.push(Finding{ kind: "meta".into(), key: "seat_ip".into(), value: seat_ip.clone(), severity: "info".into() });
        // also store a device_key you can join across submissions later
        findings.push(Finding{ kind: "meta".into(), key: "device_key".into(), value: seat_ip, severity: "info".into() });
    }

    if ai_hits_total > 0 {
        findings.push(Finding{ kind: "anomaly".into(), key: "ai_hits_total".into(), value: ai_hits_total.to_string(), severity: "warn".into() });
        for (bd, cnt) in top_k(&ai_domains, 10) {
            findings.push(Finding{ kind: "net".into(), key: "ai_domain".into(), value: format!("{bd}:{cnt}"), severity: "warn".into() });
        }
        let dns_total = domains.values().sum::<usize>() as f64;
        if dns_total > 0.0 {
            let pct = ((ai_hits_total as f64) * 100.0 / dns_total).round() as i64;
            findings.push(Finding{ kind: "anomaly".into(), key: "ai_ratio_percent".into(), value: pct.to_string(), severity: if pct >= 10 { "warn".into() } else { "info".into() } });
        }
    }

    let all_net = src_ips.values().sum::<usize>();
    let localhost = src_ips.get("127.0.0.1").copied().unwrap_or(0);
    if all_net > 0 && localhost as f64 / all_net as f64 > 0.8 {
        findings.push(Finding{ kind: "anomaly".into(), key: "loopback_dominated".into(), value: format!("{localhost}/{all_net}"), severity: "warn".into() });
    }

    // intensity last
    findings.push(Finding{ kind: "net".into(), key: "burst_max_events_per_min".into(), value: burst_max_per_min.to_string(), severity: "info".into() });
    findings.push(Finding{ kind: "net".into(), key: "final5_net_events".into(), value: final5_net_events.to_string(), severity: if final5_net_events > 50 { "warn".into() } else { "info".into() } });

    Ok(AnalysisResult{ findings, now_rfc3339: now_rfc3339 })
}


pub fn process_pending(data: &web::Data<AppState>) -> Result<(), String> {

    // pick one oldest submission with status received
    let conn = data
        .pool
        .get()
        .map_err(|e| e.to_string())?;
    
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;

    let sub: Option<(String, String)> = tx
        .query_row(
            "SELECT s.id, l.fs_path
             FROM submissions s
             JOIN logs l ON l.submission_ref = s.id
             WHERE s.status = 'received'
             ORDER BY s.created_at ASC
             LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let Some((sub_id, fs_path)) = sub else {
        tx.commit().map_err(|e| e.to_string())?;
        return Ok(());
    };

    // mark as processing
    tx.execute("UPDATE submissions SET status = 'processing' WHERE id = ?1", [&sub_id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    // analyze outside the TX
    let analysis = analyze_zip(PathBuf::from(&fs_path))
        .map_err(|e| format!("analyze {fs_path}: {e}"))?;

    // write findings and finalize
    let conn = data.pool.get().map_err(|e| e.to_string())?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

    for f in analysis.findings {
        tx.execute(
            "INSERT INTO findings(id, submission_ref, kind, key, value, severity, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                &sub_id,
                f.kind,
                f.key,
                f.value,
                f.severity,
                analysis.now_rfc3339
            ],
        )
        .map_err(|e| e.to_string())?;
    }

    tx.execute("UPDATE submissions SET status = 'processed' WHERE id = ?1", [&sub_id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    // move file last, after DB is durable
    let src = PathBuf::from(&fs_path);
    let dst = data.processed_dir.join(
        src.file_name().unwrap_or_default()
    );
    fs::rename(&src, &dst).map_err(|e| format!("move {} -> {}: {e}", src.display(), dst.display()))?;

    Ok(())
}
