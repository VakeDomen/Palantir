use actix_web::{get, web, HttpResponse, Responder};
use rusqlite::params;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

use crate::{routes::auth::Authorized, AppState};


#[get("/admin/assignment/{aid}/stats_activity")]
pub async fn stats_activity(
    _: Authorized,
    data: web::Data<AppState>, 
    path: web::Path<String>
) -> impl Responder {
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
