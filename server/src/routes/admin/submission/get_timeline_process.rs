use std::{collections::HashMap, io::{BufRead, BufReader}};

use actix_web::{get, web, HttpResponse, Responder};
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

use crate::routes::admin::util::{consts::{CHEAT_HIGHLIGHT_PROCS, SYSTEM_HIDE_PROCS}, point::Point, zip::open_processed_zip_by_submission};


#[derive(Serialize)]
struct ProcSeg { 
    start: i128, 
    end: i128 
} 


#[derive(Serialize)]
struct ProcRow { 
    label: String, 
    segments: Vec<ProcSeg> 
}


#[derive(Serialize)]
struct ProcPayload {
    labels: Vec<String>,
    rows: Vec<ProcRow>,
    tmin: i128,
    tmax: i128,
}


#[get("/admin/submissions/{id}/proc_timeline")]
pub async fn proc_timeline_fragment(
    data: web::Data<crate::AppState>,
    path: web::Path<String>
) -> impl Responder {
    let id = path.into_inner();
    let mut ctx = tera::Context::new();
    ctx.insert("id", &id);
    let cheat_json = serde_json::to_string(&CHEAT_HIGHLIGHT_PROCS).unwrap();
    let system_json = serde_json::to_string(&SYSTEM_HIDE_PROCS).unwrap();
    ctx.insert("CHEAT_HIGHLIGHT_JSON", &cheat_json);
    ctx.insert("SYSTEM_HIDE_JSON", &system_json);
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