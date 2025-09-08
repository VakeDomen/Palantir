use actix_session::Session;
use actix_web::{get, web, HttpResponse, Responder};
use tera::Context;

use crate::{db, routes::auth::Authorized, template, AppState};



#[get("/admin")]
pub async fn admin_root(_: Authorized) -> impl Responder {
    HttpResponse::Found()
        .append_header(("Location", "/admin/dashboard"))
        .finish()
}

#[get("/admin/dashboard")]
pub async fn dashboard(
    _: Authorized, 
    session: Session, 
    data: web::Data<AppState>
) -> impl Responder {
    let prof = session.get::<String>("prof")
        .unwrap()
        .unwrap();
    let subs = db::list_subscription_summaries(&data.pool, &prof)
        .unwrap_or_default();
    
    let mut ctx = Context::new();
    ctx.insert("subs", &subs);
    match data.tera.render("dashboard/page.html", &ctx) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
