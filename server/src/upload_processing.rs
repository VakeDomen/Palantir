use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

use actix_web::web;
use log::{debug, error, info, warn};
use rusqlite::OptionalExtension;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;
use zip::ZipArchive;

use crate::{
    routes::admin::util::consts::*, AppState
};

struct Finding {
    kind: String,
    key: String,
    value: String,
}

struct AnalysisResult {
    findings: Vec<Finding>,
    now_rfc3339: String,
}

pub fn pretty_rfc3339(s: &str) -> String {
    let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) else {
        return s.to_string();
    };
    let offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let local = dt.to_offset(offset);
    let fmt =
        time::format_description::parse("[month repr:short] [day], [year] [hour]:[minute]").unwrap();
    local.format(&fmt).unwrap_or_else(|_| s.to_string())
}

pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

fn analyze_zip(zip_path: PathBuf) -> Result<AnalysisResult, String> {
    info!("analyze_zip: starting analysis for {}", zip_path.display());
     
    use std::io::Read;
    
    let mut zip_file = std::fs::File::open(&zip_path).map_err(|e| {
        error!("analyze_zip: failed to open zip {}: {}", zip_path.display(), e);
        format!("open zip {}: {e}", zip_path.display())
    })?;
    
    let mut archive = ZipArchive::new(&mut zip_file).map_err(|e| {
        error!("analyze_zip: failed to read zip {}: {}", zip_path.display(), e);
        format!("read zip {}: {e}", zip_path.display())
    })?;

    // optional manifest
    let mut _manifest_json = String::new();
    if let Ok(mut f) = archive.by_name("manifest.json") {
        f.read_to_string(&mut _manifest_json).map_err(|e| e.to_string())?;
    }

    if let Ok(mut f) = archive.by_name("manifest.json") {
        if let Err(e) = f.read_to_string(&mut _manifest_json) {
            warn!("analyze_zip: could not read manifest.json in {}: {}", zip_path.display(), e);
        }
    } else {
        debug!("analyze_zip: no manifest.json in {}", zip_path.display());
    }

    // log
    let mut log_buf = String::new();
    if let Ok(mut f) = archive.by_name("snapshot/palantir.log") {
        if let Err(e) = f.read_to_string(&mut log_buf) {
            error!("analyze_zip: failed reading snapshot/palantir.log in {}: {}", zip_path.display(), e);
            return Err(e.to_string());
        }
    } else {
        error!("analyze_zip: missing snapshot/palantir.log in {}", zip_path.display());
        return Err("missing snapshot/palantir.log".to_string());
    }

    // time trackers
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;
    let mut ts_prev: Option<OffsetDateTime> = None;
    let mut max_idle: i64 = 0;
    let mut event_ts: Vec<OffsetDateTime> = Vec::new();

    // proc trackers
    let mut proc_starts = 0;
    let mut proc_stops = 0;
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

    // category counters
    let mut qna_hits = 0usize;
    let mut code_host_hits = 0usize;
    let mut search_hits = 0usize;
    let mut pkg_hits = 0usize;
    let mut cloud_hits = 0usize;

    for (lineno, raw) in log_buf.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() { 
            continue; 
        }

        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                warn!("analyze_zip: JSON parse error at line {} in {}: {} | snippet='{}'",
                    lineno+1, zip_path.display(), e, &line.chars().take(120).collect::<String>());
                continue;
            }
        };

        let kind = v
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("");
        let ts_s = v
            .get("ts")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();

        if ts_s.is_empty() {
            debug!("analyze_zip: missing ts at line {} kind='{}' in {}", lineno+1, kind, zip_path.display());
        } else {
            if first_ts.is_none() { 
                first_ts = Some(ts_s.clone()); 
            }
            
            last_ts = Some(ts_s.clone());

            match parse_rfc3339(&ts_s) {
                Some(curr) => {
                    if let Some(prev) = ts_prev {
                        let gap = (curr - prev).whole_seconds();
                        if gap > max_idle { max_idle = gap; }
                    }
                    ts_prev = Some(curr);
                    event_ts.push(curr);
                }
                None => {
                    warn!("analyze_zip: bad timestamp at line {} -> '{}' in {}", lineno+1, ts_s, zip_path.display());
                }
            }
        }

        match kind {
            "proc" => {
                let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
                let comm =
                    v.get("comm").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
                let pid = v.get("pid").and_then(|x| x.as_i64()).unwrap_or(-1);

                if action == "start" {
                    proc_starts += 1;
                    *procs.entry(comm.clone()).or_default() += 1;
                    if name_is_in(&comm, BROWSERS) {
                        had_browser = true;
                    }
                    if name_is_in(&comm, SHELLS) {
                        shell_count += 1;
                    }
                    if name_is_in(&comm, REMOTE_TOOLS) {
                        remote_flag = true;
                    }
                    if name_is_in(&comm, SSH_LIKE) {
                        ssh_flag = true;
                    }
                    if name_is_in(&comm, DOWNLOAD_TOOLS) {
                        download_tool_count += 1;
                    }
                    if let Some(t) = parse_rfc3339(&ts_s) {
                        pid_start.insert(pid, (comm.clone(), t));
                        orphaned.insert(pid);
                    }
                } else if action == "stop" {
                    proc_stops += 1;
                    if !orphaned.remove(&pid) {
                        debug!("analyze_zip: stop for pid={} that wasn't marked running (line ~{})", pid, lineno+1);
                    }
                    if let Some((c0, t0)) = pid_start.remove(&pid) {
                        if let Some(t1) = parse_rfc3339(&ts_s) {
                            let secs = (t1 - t0)
                                .whole_seconds()
                                .max(0);
                            
                            *comm_runtime.entry(c0.clone()).or_default() += secs;

                            if name_is_in(&c0, BROWSERS) {
                                browser_runtime_sec += secs;
                                browser_intervals.push((t0, t1));
                            }
                            
                            if name_is_in(&c0, SHELLS) {
                                shell_intervals.push((t0, t1));
                            }

                        } else {
                            warn!("analyze_zip: bad stop timestamp for pid={} comm='{}' at line {} in {}",
                                pid, c0, lineno+1, zip_path.display());
                        }
                    } else {
                        warn!("analyze_zip: stop event without start for pid={} at line {} in {}",
                            pid, lineno+1, zip_path.display());
                    }
                }

            }
            "net" => {
                total_net_events += 1;
                if let Some(d) = v
                    .get("dns_qname")
                    .and_then(|x| x.as_str()) 
                {
                    let host = d.to_string();
                    *domains.entry(host.clone()).or_default() += 1;

                    let base = base_domain_guess(&host);
                    if !base.contains('.') {
                        debug!("analyze_zip: suspicious base domain derivation '{}' from host='{}'", base, host);
                    }



                    if AI_PROVIDER_BASES.iter().any(|s| base == *s) {
                        ai_hits_total += 1;
                        *ai_domains.entry(base.clone()).or_default() += 1;
                    }
                    if SEARCH_BASES.iter().any(|s| base == *s) {
                        search_hits += 1;
                    }
                    if QNA_BASES.iter().any(|s| base == *s) {
                        qna_hits += 1;
                    }
                    if CODE_HOST_BASES.iter().any(|s| base == *s) {
                        code_host_hits += 1;
                    }
                    if PKG_BASES.iter().any(|s| base == *s) {
                        pkg_hits += 1;
                    }
                    if CLOUD_BASES.iter().any(|s| base == *s) {
                        cloud_hits += 1;
                    }
                }
                if let Some(ip) = v.get("src_ip").and_then(|x| x.as_str()) {
                    *src_ips.entry(ip.to_string()).or_default() += 1;
                }
            }
            _ => {
                warn!("analyze_zip: unknown kind='{}' (line ~{}) in {}", kind, lineno+1, zip_path.display());
            }
        }
    }


    if !orphaned.is_empty() {
        warn!("analyze_zip: {} processes never stopped (pids: first few {:?}) in {}",
            orphaned.len(),
            orphaned.iter().take(5).collect::<Vec<_>>(),
            zip_path.display());
    }


    // helpers
    fn top_k(map: &HashMap<String, usize>, k: usize) -> Vec<(String, usize)> {
        let mut v: Vec<_> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(k);
        v
    }
    fn overlaps(
        a: &(OffsetDateTime, OffsetDateTime),
        b: &(OffsetDateTime, OffsetDateTime),
    ) -> bool {
        a.0 <= b.1 && b.0 <= a.1
    }

    // intensity
    let burst_max_per_min = if event_ts.is_empty() {
        debug!("analyze_zip: no timestamps collected from log in {}", zip_path.display());
        0
    } else {
        let mut by_min: HashMap<i64, i64> = HashMap::new();
        for t in &event_ts {
            let m = t.unix_timestamp() / 60;
            *by_min.entry(m).or_default() += 1;
        }
        *by_min.values().max().unwrap_or(&0)
    };


    let final5_net_events = if let (Some(a), Some(b)) =
        (first_ts.as_deref().and_then(parse_rfc3339), last_ts.as_deref().and_then(parse_rfc3339))
    {
        let cutoff = b - time::Duration::minutes(5);
        event_ts.iter().filter(|t| **t >= cutoff && **t <= b).count() as i64
    } else {
        0
    };

    // seat IP
    let seat_ip_opt = src_ips
        .iter()
        .filter(|(ip, _)| is_private_ipv4(ip))
        .max_by_key(|(_, c)| **c)
        .map(|(ip, _)| ip.clone());

    if let Some(ip) = &seat_ip_opt {
        debug!("analyze_zip: selected seat_ip={}", ip);
    } else {
        debug!("analyze_zip: no private seat_ip detected");
    }


    // build findings
    let mut findings = Vec::new();
    let now_rfc3339 =
        OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "now".to_string());

    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_QNA_HITS.into(),
        value: qna_hits.to_string(),
    });

    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_CODE_HOST_HITS.into(),
        value: code_host_hits.to_string(),
    });

    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_SEARCH_HITS.into(),
        value: search_hits.to_string(),
    });

    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_PKG_HITS.into(),
        value: pkg_hits.to_string(),
    });

    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_CLOUD_HITS.into(),
        value: cloud_hits.to_string(),
    });


    findings.push(Finding {
        kind: KIND_META.into(),
        key: FK_ZIP_NAME.into(),
        value: zip_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    });

    // zip name
    findings.push(Finding {
        kind: KIND_META.into(),
        key: FK_ZIP_NAME.into(),
        value: zip_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    });

    // timestamps
    if let Some(ts) = &first_ts {
        findings.push(Finding {
            kind: KIND_META.into(),
            key: FK_FIRST_TS.into(),
            value: ts.clone(),
        });
    }
    if let Some(ts) = &last_ts {
        findings.push(Finding {
            kind: KIND_META.into(),
            key: FK_LAST_TS.into(),
            value: ts.clone(),
        });
    }

    // duration & req/min
    if let (Some(a), Some(b)) =
        (first_ts.as_deref().and_then(parse_rfc3339), last_ts.as_deref().and_then(parse_rfc3339))
    {
        let mins = (b - a).whole_minutes().max(0);
        findings.push(Finding {
            kind: KIND_META.into(),
            key: FK_DURATION_MINUTES.into(),
            value: mins.to_string(),
        });

        if mins > 0 {
            let rpm = (total_net_events as i64) / mins.max(1);
            findings.push(Finding {
                kind: KIND_NET.into(),
                key: FK_REQUESTS_PER_MIN.into(),
                value: rpm.to_string(),
            });
        }
    }

    // idle time
    findings.push(Finding {
        kind: KIND_META.into(),
        key: FK_MAX_IDLE_SECONDS.into(),
        value: max_idle.to_string(),
    });

    // proc totals
    findings.push(Finding {
        kind: KIND_PROC.into(),
        key: FK_TOTAL_PROC_STARTS.into(),
        value: proc_starts.to_string(),
    });
    findings.push(Finding {
        kind: KIND_PROC.into(),
        key: FK_TOTAL_PROC_STOPS.into(),
        value: proc_stops.to_string(),
    });

    // top procs
    for (comm, cnt) in top_k(&procs, 10) {
        findings.push(Finding {
            kind: KIND_PROC.into(),
            key: FK_TOP_PROC.into(),
            value: format!("{comm}:{cnt}"),
        });
    }

    // browser runtime + presence
    if browser_runtime_sec > 0 {
        findings.push(Finding {
            kind: KIND_PROC.into(),
            key: FK_BROWSER_RUNTIME_SECONDS.into(),
            value: browser_runtime_sec.to_string(),
        });
    }
    findings.push(Finding {
        kind: KIND_PROC.into(),
        key: FK_HAD_BROWSER.into(),
        value: had_browser.to_string(),
    });

    // shells / downloads / remote / ssh
    if shell_count > 0 {
        findings.push(Finding {
            kind: KIND_PROC.into(),
            key: FK_SHELL_INVOCATIONS.into(),
            value: shell_count.to_string(),
        });
    }
    if download_tool_count > 0 {
        findings.push(Finding {
            kind: KIND_PROC.into(),
            key: FK_EXTERNAL_DOWNLOAD_TOOL_COUNT.into(),
            value: download_tool_count.to_string(),
        });
    }
    if remote_flag {
        findings.push(Finding {
            kind: KIND_ANOMALY.into(),
            key: FK_REMOTE_COLLAB_TOOL_SEEN.into(),
            value: "true".into(),
        });
    }
    if ssh_flag {
        findings.push(Finding {
            kind: KIND_ANOMALY.into(),
            key: FK_SSH_ACTIVITY.into(),
            value: "true".into(),
        });
    }

    // net counts
    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_TOTAL_NET_EVENTS.into(),
        value: total_net_events.to_string(),
    });
    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_UNIQUE_DOMAINS.into(),
        value: domains.len().to_string(),
    });
    for (d, cnt) in top_k(&domains, 10) {
        findings.push(Finding {
            kind: KIND_NET.into(),
            key: FK_TOP_DOMAIN.into(),
            value: format!("{d}:{cnt}"),
        });
    }

    // top src IPs
    for (ip, cnt) in top_k(&src_ips, 5) {
        findings.push(Finding {
            kind: KIND_NET.into(),
            key: FK_TOP_SRC_IP.into(),
            value: format!("{ip}:{cnt}"),
        });
    }

    // seat ip / device key (best private IP)
    if let Some(seat_ip) = seat_ip_opt {
        findings.push(Finding {
            kind: KIND_META.into(),
            key: FK_SEAT_IP.into(),
            value: seat_ip.clone(),
        });
        findings.push(Finding {
            kind: KIND_META.into(),
            key: FK_DEVICE_KEY.into(),
            value: seat_ip,
        });
    }

    // AI totals / domains / ratio
    if ai_hits_total > 0 {
        findings.push(Finding {
            kind: KIND_ANOMALY.into(),
            key: FK_AI_HITS_TOTAL.into(),
            value: ai_hits_total.to_string(),
        });
        for (bd, cnt) in top_k(&ai_domains, 10) {
            findings.push(Finding {
                kind: KIND_NET.into(),
                key: FK_AI_DOMAIN.into(),
                value: format!("{bd}:{cnt}"),
            });
        }
        let dns_total = domains.values().sum::<usize>() as f64;
        if dns_total > 0.0 {
            let pct = ((ai_hits_total as f64) * 100.0 / dns_total).round() as i64;
            findings.push(Finding {
                kind: KIND_ANOMALY.into(),
                key: FK_AI_RATIO_PERCENT.into(),
                value: pct.to_string(),
            });
        }
    }

    // loopback dominance
    let all_net = src_ips.values().sum::<usize>();
    let localhost = src_ips.get("127.0.0.1").copied().unwrap_or(0);
    if all_net > 0 && (localhost as f64) / (all_net as f64) > 0.8 {
        findings.push(Finding {
            kind: KIND_ANOMALY.into(),
            key: FK_LOOPBACK_DOMINATED.into(),
            value: format!("{localhost}/{all_net}"),
        });
    }

    // intensity
    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_BURST_MAX_EVENTS_PER_MIN.into(),
        value: burst_max_per_min.to_string(),
    });
    findings.push(Finding {
        kind: KIND_NET.into(),
        key: FK_FINAL5_NET_EVENTS.into(),
        value: final5_net_events.to_string(),
    });

    info!(
        "analyze_zip: done {} | events={} domains={} ai_hits={} procs_started={} procs_stopped={}",
        zip_path.display(), total_net_events, domains.len(), ai_hits_total, proc_starts, proc_stops
    );

    Ok(AnalysisResult {
        findings,
        now_rfc3339,
    })
}

pub fn process_pending(data: &web::Data<AppState>) -> Result<(), String> {
    let conn = data.pool.get().map_err(|e| e.to_string())?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

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

    tx.execute("UPDATE submissions SET status = 'processing' WHERE id = ?1", [&sub_id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    let analysis = analyze_zip(PathBuf::from(&fs_path))
        .map_err(|e| format!("analyze {fs_path}: {e}"))?;

    let conn = data.pool.get().map_err(|e| e.to_string())?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

    for f in analysis.findings {
        tx.execute(
            "INSERT INTO findings(id, submission_ref, kind, key, value, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                &sub_id,
                f.kind,
                f.key,
                f.value,
                analysis.now_rfc3339
            ],
        )
        .map_err(|e| e.to_string())?;
    }

    tx.execute("UPDATE submissions SET status = 'processed' WHERE id = ?1", [&sub_id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    let src = PathBuf::from(&fs_path);
    let dst = data.processed_dir.join(src.file_name().unwrap_or_default());
    fs::rename(&src, &dst)
        .map_err(|e| format!("move {} -> {}: {e}", src.display(), dst.display()))?;

    Ok(())
}
