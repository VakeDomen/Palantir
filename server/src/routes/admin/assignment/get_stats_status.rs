use actix_web::{get, web, HttpResponse, Responder};
use rusqlite::params;

use crate::AppState;

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
