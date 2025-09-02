use actix_web::{get, web, HttpResponse, Responder};

use crate::{db::fetch_durations_minutes, AppState};


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