use std::collections::HashMap;

// src/routes/admin.rs (or routes/submission.rs)
use actix_web::{get, web, HttpResponse, Responder};
use crate::{db::{self, FindingRow}, AppState};

#[get("/admin/submissions/{id}/artifacts")]
pub async fn submission_artifacts_frag(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();

    // fetch artifacts + findings
    let logs = match db::list_logs_for_submission(&data.pool, &id) {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().body(e),
    };
    let findings = match db::list_findings_for_submission(&data.pool, &id) {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().body(e),
    };

    

    let mut ctx = tera::Context::new();
    let mut by_kind: HashMap<String, Vec<FindingRow>> = HashMap::new();
    for f in findings.iter().cloned() {
        by_kind.entry(f.kind.clone()).or_default().push(f);
    }
    println!("by_kind: {:#?}", by_kind);
    
    ctx.insert("logs", &logs);
    ctx.insert("by_kind", &by_kind);
    match data.tera.render("submission/artifacts.html", &ctx) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e)   => HttpResponse::InternalServerError().body(format!("render error: {e}")),
    }
}
