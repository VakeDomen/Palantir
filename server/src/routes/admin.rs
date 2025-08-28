use actix_web::{get, post, web, HttpResponse, Responder};
use actix_session::Session;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::AppState;
use crate::db; // new

#[get("/admin")]
pub async fn dashboard(session: Session, data: web::Data<AppState>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return HttpResponse::Found().append_header(("Location", "/admin/login")).finish();
    }
    let prof = session.get::<String>("prof").unwrap().unwrap();

    let subs = db::list_subscription_summaries(&data.pool, &prof).unwrap_or_default();
    let mut ctx = tera::Context::new();
    ctx.insert("subs", &subs);
    let html = data.tera.render("dashboard.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
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
    let mut ctx = tera::Context::new();
    ctx.insert("subs", &subs);
    let frag = data.tera.render("subs_list.html", &ctx).unwrap();
    HttpResponse::Ok().body(frag)
}

#[post("/admin/unsubscribe")]
pub async fn unsubscribe(session: Session, data: web::Data<AppState>, form: web::Form<SubForm>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() { return HttpResponse::Unauthorized().finish(); }
    let prof = session.get::<String>("prof").unwrap().unwrap();
    let aid = form.assignment_id.trim().to_string();

    let _ = db::unsubscribe(&data.pool, &prof, &aid);

    let subs = db::list_subscription_summaries(&data.pool, &prof).unwrap_or_default();
    let mut ctx = tera::Context::new();
    ctx.insert("subs", &subs);
    let frag = data.tera.render("subs_list.html", &ctx).unwrap();
    HttpResponse::Ok().body(frag)
}

#[get("/admin/assignment/{aid}")]
pub async fn assignment_page(session: Session, data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return HttpResponse::Found().append_header(("Location", "/admin/login")).finish();
    }
    let aid = path.into_inner();

    let rows = db::list_submissions_by_assignment(&data.pool, &aid).unwrap_or_default();

    let mut ctx = tera::Context::new();
    ctx.insert("rows", &rows);

    let mut html = String::from(
        r#"<html><head><meta charset="utf-8"><title>Assignment</title></head><body>
        <a href="/admin">Back</a>
        <h2>Assignment "#,
    );
    html.push_str(&aid);
    html.push_str(r#"</h2>
      <table border="1" cellpadding="6">
        <tr><th>id</th><th>student</th><th>time</th><th>status</th><th></th></tr>
        "#);
    let rows_html = data.tera.render("assign_rows.html", &ctx).unwrap();
    html.push_str(&rows_html);
    html.push_str("</table></body></html>");
    HttpResponse::Ok().body(html)
}

#[get("/admin/submissions")]
pub async fn submissions(session: Session, data: web::Data<AppState>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return actix_web::HttpResponse::Found().append_header(("Location", "/admin/login")).finish();
    }

    let rows = db::list_recent_submissions(&data.pool, 100).unwrap_or_default();

    let mut html = String::from(
        r#"<html><head><meta charset="utf-8"><title>Palantir submissions</title>
           <script src="https://unpkg.com/htmx.org@1.9.12"></script>
           </head><body><h2>Submissions</h2><a href="/admin/logout">Logout</a>
           <table border="1" cellpadding="6"><tr><th>id</th><th>submission</th><th>student</th><th>time</th><th>status</th></tr>"#,
    );
    for r in rows {
        html.push_str(&format!(
            r#"<tr>
                <td><a href="/admin/submissions/{}">{}</a></td>
                <td>{}</td><td>{}</td><td>{}</td><td>{}</td>
               </tr>"#,
            r.id, r.id, "n/a", r.student_name, r.created_at, r.status
        ));
    }
    html.push_str("</table></body></html>");
    HttpResponse::Ok().body(html)
}

#[get("/admin/submissions/{id}")]
pub async fn submission_detail(
    session: Session,
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return actix_web::HttpResponse::Found().append_header(("Location", "/admin/login")).finish();
    }
    let id = path.into_inner();

    match db::get_submission_detail(&data.pool, &id) {
        Ok(Some(info)) => {
            let logs = db::list_logs_for_submission(&data.pool, &id).unwrap_or_default();
            let mut html = String::new();
            html.push_str("<html><head><meta charset=\"utf-8\"><title>Submission</title></head><body>");
            html.push_str(&format!(
                "<h2>Submission {}</h2><p>assignment {} by {} at {} status {}</p>",
                id, info.submission_id, info.student_name, info.created_at, info.status
            ));
            html.push_str("<h3>Artifacts</h3><ul>");
            for e in logs {
                let name = e.fs_path.split('/').last().unwrap_or(&e.fs_path);
                html.push_str(&format!(
                    "<li>{} sha256 {} size {} bytes</li>",
                    name, e.sha256, e.size_bytes
                ));
            }
            html.push_str("</ul></body></html>");
            HttpResponse::Ok().body(html)
        }
        Ok(None) => HttpResponse::NotFound().body("not found"),
        Err(e) => HttpResponse::InternalServerError().body(e),
    }
}
