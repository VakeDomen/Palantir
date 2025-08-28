use actix_web::{get, post, web, HttpResponse, Responder};
use actix_session::Session;
use serde::Deserialize;
use time::OffsetDateTime;

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
    let rows = db::list_submissions_by_assignment(&data.pool, &aid).unwrap_or_default();
    match template::assignment_page(&data.tera, &aid, &rows) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.0),
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
