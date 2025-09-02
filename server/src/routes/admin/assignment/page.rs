use actix_session::Session;
use actix_web::{get, web, HttpResponse, Responder};

use crate::{db, template, AppState};


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
