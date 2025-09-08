use actix_session::Session;
use actix_web::{get, web, HttpResponse, Responder};

use crate::{db, routes::auth::Authorized, template, AppState};


#[get("/admin/submissions/{id}")]
pub async fn submission_page(
    _: Authorized,
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
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
