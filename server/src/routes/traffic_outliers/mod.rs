use actix_web::{get, web, HttpResponse, Responder};

use crate::AppState;

#[derive(serde::Serialize)]
struct NetOut {
    student: String,
    sub_id: String,
    total_net: i64,
    over_median: i64,     // total_net - median
    pctl: u8,             // percentile estimate like 97
    rscore: f64,          // robust score (mad-based)
}

#[get("/admin/assignment/{aid}/stats_outliers")]
pub async fn stats_outliers(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    use rusqlite::params;

    let aid = path.into_inner();
    let conn = match data.pool.get() {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    // Pull total_net_events per submission in this assignment
    let mut stmt = match conn.prepare(
        "SELECT s.id, s.student_name,
                COALESCE((SELECT value FROM findings
                          WHERE submission_ref = s.id AND key = 'total_net_events' LIMIT 1), '0')
         FROM submissions s
         WHERE s.submission_id = ?1"
    ) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let rows = match stmt.query_map(params![&aid], |r| {
        Ok((
            r.get::<_, String>(0)?, // id
            r.get::<_, String>(1)?, // student
            r.get::<_, String>(2)?, // total_net_events as string
        ))
    }) {
        Ok(it) => it,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let mut submision_net_events: Vec<(String, String, i64)> = Vec::new();
    for row in rows {
        let (id, student, total_net_events_string) = match row {
            Ok(v) => v,
            Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        };
        let total_net_events = total_net_events_string.parse::<i64>().unwrap_or(0);
        submision_net_events.push((id, student, total_net_events));
    }

    if submision_net_events.is_empty() {
        let mut ctx = tera::Context::new();
        ctx.insert("rows", &Vec::<NetOut>::new());
        let html = match data.tera.render("assignment/stats_outliers.html", &ctx) {
            Ok(h) => h,
            Err(e) => return HttpResponse::InternalServerError().body(format!("render error: {e}")),
        };
        return HttpResponse::Ok().body(html);
    }

    let totals: Vec<i64> = submision_net_events
        .iter()
        .map(|t| t.2)
        .collect();

    let med = median_i64(totals.clone());
    
    let abs_dev: Vec<i64> = totals
        .iter()
        .map(|&x| (x - med).abs())
        .collect();
    let mad = median_i64(abs_dev);

    // thresholds
    let p95 = percentile_i64(totals.clone(), 95.0);
    let robust_cut = med + 3 * mad.max(1);
    let cut = robust_cut.max(p95);

    // precompute percentiles to display
    // quick-and-dirty percentile estimate from the sorted list
    let mut sorted = totals.clone();
    sorted.sort_unstable();
    let n = sorted.len() as f64;
    let pct_of = |x: i64| -> u8 {
        // position of last value <= x
        let idx = match sorted.binary_search(&x) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let p = ((idx as f64) / (n - 1.0).max(1.0)) * 100.0;
        p.round() as u8
    };

    // build flagged rows
    let mut flagged: Vec<NetOut> = submision_net_events.into_iter()
        .filter(|(_, _, tn)| *tn >= cut)
        .map(|(id, student, tn)| {
            let rscore = if mad == 0 { 0.0 } else { (tn - med) as f64 / mad as f64 };
            NetOut {
                student,
                sub_id: id,
                total_net: tn,
                over_median: tn - med,
                pctl: pct_of(tn).min(100),
                rscore,
            }
        })
        .collect();

    // sort by how far above median, then by total
    flagged.sort_by(|a, b| b.over_median.cmp(&a.over_median).then_with(|| b.total_net.cmp(&a.total_net)));
    flagged.truncate(8);

    let mut ctx = tera::Context::new();
    ctx.insert("rows", &flagged);
    ctx.insert("median", &med);
    ctx.insert("p95", &p95);
    let html = match data.tera.render("assignment/stats_outliers.html", &ctx) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().body(format!("render error: {e}")),
    };
    HttpResponse::Ok().body(html)
}


fn median_i64(mut v: Vec<i64>) -> i64 {
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 { v[n/2] } else { ((v[n/2 - 1] + v[n/2]) / 2) }
}
fn percentile_i64(mut v: Vec<i64>, p: f64) -> i64 {
    v.sort_unstable();
    if v.is_empty() { return 0; }
    let rank = ((p.clamp(0.0, 100.0) / 100.0) * (v.len() as f64 - 1.0)).round() as usize;
    v[rank]
}