use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use actix_web::{get, post, web, HttpResponse, Responder};
use actix_session::Session;
use rusqlite::params;
use serde::Deserialize;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use time::UtcOffset;
use zip::ZipArchive;
use std::path::{Path, PathBuf};


use crate::db::fetch_durations_minutes;
use crate::template;
use crate::AppState;
use crate::db; // new


#[get("/admin")]
pub async fn dashboard(session: Session, data: web::Data<AppState>) -> impl Responder {
    if session.get::<String>("prof")
        .ok()
        .flatten()
        .is_none() 
    {
        return HttpResponse::Found()
            .append_header(("Location", "/admin/login"))
            .finish();
    }
    let prof = session.get::<String>("prof")
        .unwrap()
        .unwrap();
    let subs = db::list_subscription_summaries(&data.pool, &prof)
        .unwrap_or_default();
    
    match template::dashboard(&data.tera, &subs) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.0),
    }
}


#[derive(Deserialize)]
pub struct SubForm { pub assignment_id: String }


#[post("/admin/subscribe")]
pub async fn subscribe(session: Session, data: web::Data<AppState>, form: web::Form<SubForm>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() { return HttpResponse::Unauthorized().finish(); }
    let prof = session.get::<String>("prof").unwrap().unwrap();
    let aid = form.assignment_id.trim().to_string();
    let now = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap();

    let _ = db::subscribe(&data.pool, &prof, &aid, &now);
    let subs = db::list_subscription_summaries(&data.pool, &prof).unwrap_or_default();
    match template::subs_list(&data.tera, &subs) {
        Ok(frag) => HttpResponse::Ok().body(frag),
        Err(e) => HttpResponse::InternalServerError().body(e.0),
    }
}

#[post("/admin/unsubscribe")]
pub async fn unsubscribe(session: Session, data: web::Data<AppState>, form: web::Form<SubForm>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() { return HttpResponse::Unauthorized().finish(); }
    let prof = session.get::<String>("prof").unwrap().unwrap();
    let aid = form.assignment_id.trim().to_string();

    let _ = db::unsubscribe(&data.pool, &prof, &aid);
    let subs = db::list_subscription_summaries(&data.pool, &prof).unwrap_or_default();
    match template::subs_list(&data.tera, &subs) {
        Ok(frag) => HttpResponse::Ok().body(frag),
        Err(e) => HttpResponse::InternalServerError().body(e.0),
    }
}

#[get("/admin/assignment/{aid}")]
pub async fn assignment_page(session: Session, data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return HttpResponse::Found().append_header(("Location", "/admin/login")).finish();
    }
    let aid = path.into_inner();

    // list submissions for this assignment
    let rows = match db::list_submissions_by_assignment(&data.pool, &aid) {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().body(e),
    };

    // fetch findings in one shot
    let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let findings = match db::list_findings_for_submissions(&data.pool, &ids) {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().body(e),
    };

    // build cards
    let cards = template::build_cards(&rows, &findings);

    // render card grid
    match template::assignment_cards_page(&data.tera, &aid, &cards) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.0),
    }
}

#[get("/admin/assignment/{aid}/cards")]
pub async fn assignment_cards_fragment(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let aid = path.into_inner();
    let rows = db::list_submissions_by_assignment(&data.pool, &aid).unwrap_or_default();
    let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let findings = db::list_findings_for_submissions(&data.pool, &ids).unwrap_or_default();
    let cards = template::build_cards(&rows, &findings);

    let mut ctx = tera::Context::new();
    ctx.insert("cards", &cards);
    match data.tera.render("assignment/assignment_cards_fragment.html", &ctx) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}


#[get("/admin/submissions")]
pub async fn submissions(session: Session, data: web::Data<AppState>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return actix_web::HttpResponse::Found()
            .append_header(("Location", "/admin/login"))
            .finish();
    }

    let rows = db::list_recent_submissions(&data.pool, 100).unwrap_or_default();
    match template::submissions_page(&data.tera, &rows) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.0),
    }
}

#[get("/admin/submissions/{id}")]
pub async fn submission_detail(
    session: Session,
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return actix_web::HttpResponse::Found()
            .append_header(("Location", "/admin/login"))
            .finish();
    }
    let id = path.into_inner();

    match db::get_submission_detail(&data.pool, &id) {
        Ok(Some(info)) => {
            let logs = db::list_logs_for_submission(&data.pool, &id).unwrap_or_default();
            match template::submission_detail_page(&data.tera, &id, &info, &logs) {
                Ok(html) => HttpResponse::Ok().body(html),
                Err(e) => HttpResponse::InternalServerError().body(e.0),
            }
        }
        Ok(None) => HttpResponse::NotFound().body("not found"),
        Err(e) => HttpResponse::InternalServerError().body(e),
    }
}


#[get("/admin/submissions/{id}/net_timeline")]
pub async fn net_timeline_fragment(
    data: web::Data<AppState>,
    path: web::Path<String>
) -> impl Responder {
    let id = path.into_inner();
    let mut ctx = tera::Context::new();
    ctx.insert("id", &id);
    match data.tera.render("submission/timeline_network.html", &ctx) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// routes/submission_charts.rs (continued)

#[derive(Serialize)]
struct Point { t: String, total: i32, ai: i32, ma100: f32 }

#[get("/admin/submissions/{id}/net_timeline.json")]
pub async fn net_timeline_json(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();

    // locate the uploaded zip path for this submission
    let conn = match data.pool.get() {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };
    let path: String = match conn.query_row(
        "SELECT fs_path FROM logs WHERE submission_ref = ?1 ORDER BY rowid ASC LIMIT 1",
        params![&id],
        |r| r.get(0),
    ) {
        Ok(p) => p,
        Err(_) => return HttpResponse::Ok().json(Vec::<Point>::new()),
    };


    let filename: String = match conn.query_row(
        "SELECT fs_path FROM logs WHERE submission_ref = ?1 ORDER BY rowid ASC LIMIT 1",
        params![&id],
        |r| {
            let full: String = r.get(0)?;
            // just keep the filename
            Ok(std::path::Path::new(&full)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned())
        },
    ) {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().body(format!("query: {}", e))
    };

    // now open from processed_uploads
    let zip_path = data.processed_dir.join(&filename);
    let file = match File::open(&zip_path) {
        Ok(f) => f,
        Err(e) => return HttpResponse::InternalServerError()
            .body(format!("open zip {}: {}", zip_path.display(), e))
    };

    let mut zip = match ZipArchive::new(file) {
        Ok(zip) => zip,
        Err(e) => return HttpResponse::InternalServerError().body(format!("zip: {}", e))
    };


    let mut log = match zip.by_name("snapshot/palantir.log") {
        Ok(f) => BufReader::new(f),
        Err(_) => return HttpResponse::Ok().json(Vec::<Point>::new()),
    };

    // classify AI domains
    fn is_ai_domain(d: &str) -> bool {
        let d = d.to_ascii_lowercase();
        let hits = [
            "openai.com","chatgpt.com","anthropic.com","claude.ai",
            "gemini.google.com","googleapis.com","googleai","ai.google",
            "huggingface.co","cohere.ai","replicate.com","perplexity.ai",
            "openrouter.ai","stability.ai","midjourney.com"
        ];
        hits.iter().any(|s| d.contains(s))
    }

    // bucket by minute in local time for user-friendly x labels
    let local = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    use std::collections::BTreeMap;
    let mut buckets: BTreeMap<String, (i32, i32)> = BTreeMap::new();

    let mut line = String::new();
    while let Ok(n) = log.read_line(&mut line) {
        if n == 0 { break; }
        // only net lines
        if !line.contains("\"kind\":\"net\"") {
            line.clear();
            continue;
        }
        // quick and safe parse
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(x) => x,
            Err(_) => { line.clear(); continue; }
        };
        let ts = match v.get("ts").and_then(|x| x.as_str()) {
            Some(s) => s, None => { line.clear(); continue; }
        };
        let minute_key = match OffsetDateTime::parse(ts, &Rfc3339)
            .map(|dt| dt.to_offset(local))
            .ok()
            .and_then(|dt| Some(format!("{:04}-{:02}-{:02} {:02}:{:02}",
                dt.year(), dt.month() as u8, dt.day(), dt.hour(), dt.minute())))
        {
            Some(k) => k,
            None => { line.clear(); continue; }
        };
        let domain = v.get("dns_qname").and_then(|x| x.as_str()).unwrap_or("");
        let entry = buckets.entry(minute_key).or_insert((0, 0));
        entry.0 += 1;
        if is_ai_domain(domain) {
            entry.1 += 1;
        }
        line.clear();
    }

    // compute MA(100) over total
    let mut out: Vec<Point> = Vec::with_capacity(buckets.len());
    for (t, (tot, ai)) in buckets {
        out.push(Point { t, total: tot, ai, ma100: 0.0 });
    }
    let w = 100usize;
    if !out.is_empty() {
        let mut acc: i64 = 0;
        let mut q: std::collections::VecDeque<i32> = std::collections::VecDeque::new();
        for i in 0..out.len() {
            acc += out[i].total as i64;
            q.push_back(out[i].total);
            if q.len() > w {
                acc -= q.pop_front().unwrap() as i64;
            }
            let denom = q.len() as f32;
            out[i].ma100 = if denom > 0.0 { (acc as f32) / denom } else { 0.0 };
        }
    }

    HttpResponse::Ok().json(out)
}



#[derive(Serialize)]
struct ProcSeg { start: i128, end: i128 } // ms epoch
#[derive(Serialize)]
struct ProcRow { label: String, segments: Vec<ProcSeg> }
#[derive(Serialize)]
struct ProcPayload {
    labels: Vec<String>,
    rows: Vec<ProcRow>,
    tmin: i128,
    tmax: i128,
}

// helper that opens the processed zip by file name
fn open_processed_zip_by_submission(
    data: &crate::AppState,
    submission_id: &str
) -> Result<ZipArchive<File>, String> {
    let conn = data.pool.get().map_err(|e| e.to_string())?;
    let full: String = conn.query_row(
        "SELECT fs_path FROM logs WHERE submission_ref = ?1 ORDER BY rowid ASC LIMIT 1",
        params![&submission_id],
        |r| r.get(0),
    ).map_err(|e| e.to_string())?;
    let fname = Path::new(&full).file_name().ok_or("bad file name")?;
    let zip_path: PathBuf = data.processed_dir.join(fname);
    let file = File::open(&zip_path).map_err(|e| format!("open {}: {}", zip_path.display(), e))?;
    ZipArchive::new(file).map_err(|e| format!("zip: {e}"))
}

#[get("/admin/submissions/{id}/proc_timeline")]
pub async fn proc_timeline_fragment(
    data: web::Data<crate::AppState>,
    path: web::Path<String>
) -> impl Responder {
    let id = path.into_inner();
    let mut ctx = tera::Context::new();
    ctx.insert("id", &id);
    match data.tera.render("submission/timeline_process.html", &ctx) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/admin/submissions/{id}/proc_timeline.json")]
pub async fn proc_timeline_json(
    data: web::Data<crate::AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();

    // open zip and palantir.log
    let mut zip = match open_processed_zip_by_submission(&data, &id) {
        Ok(z) => z,
        Err(e) => return HttpResponse::InternalServerError().body(e),
    };
    
    let mut log = match zip.by_name("snapshot/palantir.log") {
        Ok(f) => BufReader::new(f),
        Err(_) => return HttpResponse::Ok().json(Vec::<Point>::new()),
    };

    // parse events and build intervals
    let mut line = String::new();
    let mut open: HashMap<i32, (String, OffsetDateTime)> = HashMap::new(); // pid -> (comm, start)
    let mut intervals_by_comm: HashMap<String, Vec<(OffsetDateTime, OffsetDateTime)>> = HashMap::new();
    let mut global_min: Option<OffsetDateTime> = None;
    let mut global_max: Option<OffsetDateTime> = None;

    while let Ok(n) = log.read_line(&mut line) {
        if n == 0 { break; }
        if !line.contains("\"kind\":\"proc\"") { line.clear(); continue; }

        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(x) => x, Err(_) => { line.clear(); continue; }
        };
        let ts = match v.get("ts").and_then(|x| x.as_str()) {
            Some(s) => s, None => { line.clear(); continue; }
        };
        let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
        let pid    = v.get("pid").and_then(|x| x.as_i64()).unwrap_or(-1) as i32;
        let comm   = v.get("comm").and_then(|x| x.as_str()).unwrap_or("").to_string();

        let t = match OffsetDateTime::parse(ts, &Rfc3339) { Ok(t) => t, Err(_) => { line.clear(); continue; } };
        global_min = Some(global_min.map_or(t, |m| m.min(t)));
        global_max = Some(global_max.map_or(t, |m| m.max(t)));

        match action {
            "start" => { open.insert(pid, (comm, t)); }
            "stop"  => {
                if let Some((c, s)) = open.remove(&pid) {
                    let e = t;
                    intervals_by_comm.entry(c).or_default().push((s, e));
                }
            }
            _ => {}
        }

        line.clear();
    }

    // close any dangling starts at global_max
    if let Some(tmax) = global_max {
        for (_pid, (c, s)) in open.drain() {
            intervals_by_comm.entry(c).or_default().push((s, tmax));
        }
    }

    // merge small gaps per comm and compute total duration
    fn merge(mut ivals: Vec<(OffsetDateTime, OffsetDateTime)>) -> (Vec<(OffsetDateTime, OffsetDateTime)>, i128) {
        ivals.sort_by_key(|x| x.0);
        let mut out: Vec<(OffsetDateTime, OffsetDateTime)> = Vec::new();
        let mut total_ms: i128 = 0;
        let gap = time::Duration::seconds(5); // merge gaps less than 5s
        for (s, e) in ivals {
            if let Some(last) = out.last_mut() {
                if s <= last.1 + gap {
                    if e > last.1 { last.1 = e; }
                } else {
                    total_ms += (last.1 - last.0).whole_milliseconds();
                    out.push((s, e));
                }
            } else {
                out.push((s, e));
            }
        }
        if let Some(last) = out.last() {
            total_ms += (last.1 - last.0).whole_milliseconds();
        }
        (out, total_ms)
    }

    // rank by total duration and limit
    let mut rows_tmp: Vec<(String, Vec<(OffsetDateTime, OffsetDateTime)>, i128)> = Vec::new();
    for (comm, ivals) in intervals_by_comm {
        let (merged, tot) = merge(ivals);
        rows_tmp.push((comm, merged, tot));
    }
    rows_tmp.sort_by(|a, b| a.2.cmp(&b.2));
    let limit = 500;
    let rows_tmp = rows_tmp.into_iter().take(limit).collect::<Vec<_>>();

    // build payload
    let local = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let to_ms = |dt: OffsetDateTime| (dt.to_offset(local).unix_timestamp_nanos() / 1_000_000) as i128;

    let labels: Vec<String> = rows_tmp.iter().map(|x| x.0.clone()).collect();
    let mut rows: Vec<ProcRow> = Vec::new();
    let mut tmin_ms = i128::MAX;
    let mut tmax_ms = i128::MIN;

    for (label, ivals, _) in rows_tmp {
        let mut segs: Vec<ProcSeg> = Vec::new();
        for (s, e) in ivals {
            let sm = to_ms(s);
            let em = to_ms(e);
            if sm < tmin_ms { tmin_ms = sm; }
            if em > tmax_ms { tmax_ms = em; }
            segs.push(ProcSeg { start: sm, end: em });
        }
        rows.push(ProcRow { label, segments: segs });
    }

    let payload = ProcPayload {
        labels,
        rows,
        tmin: if tmin_ms == i128::MAX { 0 } else { tmin_ms },
        tmax: if tmax_ms == i128::MIN { 0 } else { tmax_ms },
    };
    HttpResponse::Ok().json(payload)
}


#[get("/admin/assignment/{aid}/stats_activity")]
pub async fn stats_activity(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let aid = path.into_inner();
    let conn = match data.pool.get() { Ok(c) => c, Err(e)=>return HttpResponse::InternalServerError().body(e.to_string()) };
    let mut stmt = conn.prepare(
        "SELECT created_at FROM submissions WHERE submission_id = ?1 ORDER BY created_at"
    ).unwrap();
    let rows = stmt.query_map(params![&aid], |r| r.get::<_, String>(0)).unwrap();

    let mut bins: std::collections::BTreeMap<String, i32> = std::collections::BTreeMap::new();
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    for row in rows {
        if let Ok(ts) = row {
            if let Ok(dt) = OffsetDateTime::parse(&ts, &Rfc3339) {
                let l = dt.to_offset(offset);
                let key = format!("{:04}-{:02}-{:02} {:02}:{:02}", l.year(), u8::from(l.month()), l.day(), l.hour(), l.minute());
                *bins.entry(key).or_default() += 1;
            }
        }
    }

    let mut ctx = tera::Context::new();
    ctx.insert("aid", &aid);
    // flatten to arrays for JS
    let labels: Vec<String> = bins.keys().cloned().collect();
    let counts: Vec<i32> = bins.values().cloned().collect();
    let labels_json = serde_json::to_string(&labels).unwrap();
    let counts_json = serde_json::to_string(&counts).unwrap();
    ctx.insert("labels_json", &labels_json);
    ctx.insert("counts_json", &counts_json);
    let html = data.tera.render("assignment/stats_activity.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
}


#[get("/admin/assignment/{aid}/stats_status")]
pub async fn stats_status(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();
    let mut stmt = conn.prepare(
        "SELECT status, COUNT(*) FROM submissions WHERE submission_id = ?1 GROUP BY status"
    ).unwrap();
    let mut labels = Vec::new();
    let mut counts = Vec::new();
    let rows = stmt.query_map(params![&aid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) .unwrap();
    for r in rows {
      let (s, n) = r.unwrap();
      labels.push(s);
      counts.push(n);
    }
    let mut ctx = tera::Context::new();
    ctx.insert("aid", &aid);
    let labels_json = serde_json::to_string(&labels).unwrap();
    let counts_json = serde_json::to_string(&counts).unwrap();
    ctx.insert("labels_json", &labels_json);
    ctx.insert("counts_json", &counts_json);
    let html = data.tera.render("assignment/stats_status.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
}


#[get("/admin/assignment/{aid}/stats_duration")]
pub async fn stats_duration(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();
    let vals = fetch_durations_minutes(&conn, &aid);
    let mut avg = 0.0;
    let mut p95 = 0;
    if !vals.is_empty() {
        let sum: i64 = vals.iter().sum();
        avg = sum as f64 / vals.len() as f64;
        let mut sorted = vals.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64)*0.95).ceil() as usize - 1;
        p95 = *sorted.get(idx.min(sorted.len()-1)).unwrap_or(&0);
    }
    let mut ctx = tera::Context::new();
    ctx.insert("aid", &aid);
    ctx.insert("count", &vals.len());
    ctx.insert("avg", &format!("{:.1}", avg));
    ctx.insert("p95", &p95);
    let html = data.tera.render("assignment/stats_duration.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
}


#[get("/admin/assignment/{aid}/stats_browser")]
pub async fn stats_browser(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();

    let mut total: i64 = 0;
    conn.query_row("SELECT COUNT(*) FROM submissions WHERE submission_id = ?1", params![&aid], |r| r.get(0)).map(|n: i64| total=n).ok();

    let mut has: i64 = 0;
    // try findings key first
    conn.query_row(
        "SELECT COUNT(*) FROM findings f JOIN submissions s ON s.id=f.submission_ref
         WHERE s.submission_id=?1 AND f.key='had_browser' AND LOWER(f.value) IN ('1','true','yes')",
        params![&aid], |r| r.get(0)).map(|n: i64| has=n).ok();

    let mut ctx = tera::Context::new();
    ctx.insert("aid", &aid);
    ctx.insert("has", &has);
    ctx.insert("total", &total);
    let html = data.tera.render("assignment/stats_browser.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
}


#[get("/admin/assignment/{aid}/stats_domains")]
pub async fn stats_domains(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();
    let mut stmt = conn.prepare(
        "SELECT f.value FROM findings f
           JOIN submissions s ON s.id=f.submission_ref
         WHERE s.submission_id = ?1 AND f.key='top_domain'"
    ).unwrap();
    let rows = stmt.query_map(params![&aid], |r| r.get::<_, String>(0)).unwrap();
    use std::collections::HashMap;
    let mut map: HashMap<String, i64> = HashMap::new();
    for r in rows {
        if let Ok(v) = r {
            if let Some((dom, cnt)) = v.split_once(':') {
                let n = cnt.parse::<i64>().unwrap_or(1);
                *map.entry(dom.to_string()).or_default() += n;
            }
        }
    }
    let mut top: Vec<(String, i64)> = map.into_iter().collect();
    top.sort_by(|a,b| b.1.cmp(&a.1));
    top.truncate(20);

    let domains: Vec<String> = top.iter().map(|x| x.0.clone()).collect();
    let counts: Vec<i64> = top.iter().map(|x| x.1).collect();

    let domains_json = serde_json::to_string(&domains).unwrap();
    let hits_json    = serde_json::to_string(&counts).unwrap();

    let mut ctx = tera::Context::new();
    ctx.insert("aid", &aid);

    // needed for the favicon <img> loop
    ctx.insert("domains", &domains);

    // needed for inline JS chart
    ctx.insert("domains_json", &domains_json);
    ctx.insert("hits_json", &hits_json);

    let html = data.tera.render("assignment/stats_domains.html", &ctx).unwrap();
    return HttpResponse::Ok().body(html);

}

#[get("/admin/assignment/{aid}/stats_shared_lan")]
pub async fn stats_shared_lan(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();

    // submissions for this assignment
    let mut q = conn.prepare("SELECT id, student_name FROM submissions WHERE submission_id = ?1").unwrap();
    let subs = q.query_map(params![&aid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap();

    use std::collections::{HashMap, HashSet};
    let mut ip_to_students: HashMap<String, HashSet<String>> = HashMap::new();

    for row in subs {
        let (sub_id, student) = row.unwrap();
        // open corresponding processed zip
        if let Ok(mut zip) = open_processed_zip_by_submission(&data, &sub_id) {
            let file_result = match zip.by_name("snapshot/palantir.log") {
                Ok(f) => f,
                Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
            };
            let mut br = std::io::BufReader::new(file_result);
            let mut line = String::new();
            while let Ok(n) = br.read_line(&mut line) {
                if n == 0 { break; }
                if !line.contains("\"kind\":\"net\"") { line.clear(); continue; }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(ip) = v.get("src_ip").and_then(|x| x.as_str()) {
                        if is_private_ip(ip) {
                            ip_to_students.entry(ip.to_string()).or_default().insert(student.clone());
                        }
                    }
                }
                line.clear();
            }
        }
    }

    // keep only IPs with more than one student
    let mut rows: Vec<(String, Vec<String>)> = ip_to_students.into_iter()
        .filter_map(|(ip, set)| {
            let v: Vec<String> = set.into_iter().collect();
            if v.len() > 1 { Some((ip, v)) } else { None }
        }).collect();
    rows.sort_by(|a,b| b.1.len().cmp(&a.1.len()));

    let mut ctx = tera::Context::new();
    ctx.insert("rows", &rows);
    let html = data.tera.render("assignment/stats_shared_lan.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
}

fn is_private_ip(ip: &str) -> bool {
    // naive private IPv4 check
    let parts: Vec<_> = ip.split('.').collect();
    if parts.len() != 4 { return false; }
    let p: Vec<i32> = parts.iter().filter_map(|s| s.parse().ok()).collect();
    if p.len() != 4 { return false; }
    (p[0] == 10)
    || (p[0] == 192 && p[1] == 168)
    || (p[0] == 172 && (16..=31).contains(&p[1]))
}
