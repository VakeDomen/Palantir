use actix_web::{get, web, HttpResponse, Responder};
use rusqlite::params;

use crate::{routes::auth::Authorized, AppState};

#[get("/admin/assignment/{aid}/stats_browser")]
pub async fn stats_browser(
    _: Authorized,
    data: web::Data<AppState>, 
    path: web::Path<String>
) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();

    let mut total: i64 = 0;
    conn.query_row("SELECT COUNT(*) FROM submissions WHERE submission_id = ?1", params![&aid], |r| r.get(0)).map(|n: i64| total=n).ok();

    let mut has: i64 = 0;
    // try findings key first
    conn.query_row(
        "SELECT COUNT(*) FROM submissions s JOIN findings f ON s.id=f.submission_ref
         WHERE s.submission_id=?1 AND f.key='had_browser' AND LOWER(f.value) IN ('1','true','yes')",
        params![&aid], |r| r.get(0)).map(|n: i64| has=n).ok();

    let mut ai_has: i64 = 0;
    conn.query_row(
        "SELECT COUNT(DISTINCT s.id) FROM findings f JOIN submissions s ON s.id=f.submission_ref
         WHERE s.submission_id=?1 AND f.key='ai_domain'",
        params![&aid], |r| r.get(0)).map(|n: i64| ai_has=n).ok();

    let mut ctx = tera::Context::new();
    ctx.insert("aid", &aid);
    ctx.insert("has", &has);
    ctx.insert("ai_has", &ai_has);
    ctx.insert("total", &total);
    let html = data.tera.render("assignment/stats_browser.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
}
