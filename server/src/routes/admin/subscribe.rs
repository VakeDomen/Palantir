use actix_session::Session;
use actix_web::{post, web, HttpResponse, Responder};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::{db, AppState};

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
    
    let mut ctx = tera::Context::new();
    ctx.insert("subs", &subs);
    match data.tera.render("dashboard/assignment_list.html", &ctx) {
        Ok(frag) => HttpResponse::Ok().body(frag),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}