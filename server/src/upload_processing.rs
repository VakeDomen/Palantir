use std::{collections::HashMap, fs, path::PathBuf};

use actix_web::web;
use rusqlite::OptionalExtension;
use uuid::Uuid;
use zip::ZipArchive;

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

fn analyze_zip(zip_path: PathBuf) -> Result<AnalysisResult, String> {
    use std::io::Read;
    let mut zip_file = std::fs::File::open(&zip_path)
        .map_err(|e| format!("open zip {}: {e}", zip_path.display()))?;
    let mut archive = ZipArchive::new(&mut zip_file)
        .map_err(|e| format!("read zip {}: {e}", zip_path.display()))?;

    // read manifest.json if present
    let mut manifest_json = String::new();
    if let Ok(mut f) = archive.by_name("manifest.json") {
        f.read_to_string(&mut manifest_json).map_err(|e| e.to_string())?;
    }

    // read log
    let mut log_buf = String::new();
    if let Ok(mut f) = archive.by_name("snapshot/palantir.log") {
        f.read_to_string(&mut log_buf).map_err(|e| e.to_string())?;
    } else {
        return Err("missing snapshot/palantir.log".to_string());
    }

    // parse lines
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;
    let mut proc_starts = 0usize;
    let mut proc_stops  = 0usize;
    let mut procs: HashMap<String, usize> = HashMap::new();

    let mut domains: HashMap<String, usize> = HashMap::new();
    let mut src_ips: HashMap<String, usize> = HashMap::new();

    for line in log_buf.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let ts = v.get("ts").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if !ts.is_empty() {
            if first_ts.is_none() { first_ts = Some(ts.clone()); }
            last_ts = Some(ts.clone());
        }
        match kind {
            "proc" => {
                let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
                let comm = v.get("comm").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
                if action == "start" { proc_starts += 1; }
                if action == "stop"  { proc_stops  += 1; }
                *procs.entry(comm).or_default() += 1;
            }
            "net" => {
                if let Some(d) = v.get("dns_qname").and_then(|x| x.as_str()) {
                    *domains.entry(d.to_string()).or_default() += 1;
                }
                if let Some(ip) = v.get("src_ip").and_then(|x| x.as_str()) {
                    *src_ips.entry(ip.to_string()).or_default() += 1;
                }
            }
            _ => {}
        }
    }

    // top N helpers
    fn top_k(map: &HashMap<String, usize>, k: usize) -> Vec<(String, usize)> {
        let mut v: Vec<_> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(k);
        v
    }

    let mut findings = Vec::new();
    let now_rfc3339 = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "now".to_string());

    // basic metrics
    findings.push(Finding{ kind: "meta".into(), key: "zip_name".into(), value: zip_path.file_name().unwrap_or_default().to_string_lossy().to_string(), severity: "info".into() });
    if let Some(ts) = &first_ts { findings.push(Finding{ kind: "meta".into(), key: "first_ts".into(), value: ts.clone(), severity: "info".into() }); }
    if let Some(ts) = &last_ts  { findings.push(Finding{ kind: "meta".into(), key: "last_ts".into(),  value: ts.clone(), severity: "info".into() }); }
    findings.push(Finding{ kind: "proc".into(), key: "total_proc_starts".into(), value: proc_starts.to_string(), severity: "info".into() });
    findings.push(Finding{ kind: "proc".into(), key: "total_proc_stops".into(),  value: proc_stops.to_string(),  severity: "info".into() });

    for (comm, cnt) in top_k(&procs, 10) {
        findings.push(Finding{ kind: "proc".into(), key: "top_proc".into(), value: format!("{comm}:{cnt}"), severity: "info".into() });
    }
    findings.push(Finding{ kind: "net".into(), key: "unique_domains".into(), value: domains.len().to_string(), severity: "info".into() });
    for (d, cnt) in top_k(&domains, 10) {
        findings.push(Finding{ kind: "net".into(), key: "top_domain".into(), value: format!("{d}:{cnt}"), severity: "info".into() });
    }
    for (ip, cnt) in top_k(&src_ips, 5) {
        findings.push(Finding{ kind: "net".into(), key: "top_src_ip".into(), value: format!("{ip}:{cnt}"), severity: "info".into() });
    }

    // simple anomalies
    let localhost = src_ips.get("127.0.0.1").copied().unwrap_or(0);
    let all_net = src_ips.values().sum::<usize>();
    if all_net > 0 && localhost as f64 / all_net as f64 > 0.8 {
        findings.push(Finding{ kind: "anomaly".into(), key: "loopback_dominated".into(), value: format!("{localhost}/{all_net}"), severity: "warn".into() });
    }

    Ok(AnalysisResult{ findings, now_rfc3339 })
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
