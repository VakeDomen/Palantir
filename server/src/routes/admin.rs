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
    match data.tera.render("components/assignment_cards_fragment.html", &ctx) {
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
    match data.tera.render("components/net_timeline.html", &ctx) {
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
    match data.tera.render("components/proc_timeline.html", &ctx) {
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
