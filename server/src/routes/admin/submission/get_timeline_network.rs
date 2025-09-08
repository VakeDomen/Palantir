use std::{fs::File, io::{BufRead, BufReader}};

use actix_web::{get, web, HttpResponse, Responder};
use rusqlite::params;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};
use zip::ZipArchive;

use crate::{routes::{admin::util::point::Point, auth::Authorized}, AppState};



#[get("/admin/submissions/{id}/net_timeline")]
pub async fn net_timeline_fragment(
    _: Authorized,
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

