use tera::{Context, Tera};

use crate::db::{LogRow, SubSummary, SubmissionDetail, SubmissionRow};

#[derive(Debug)]
pub struct RenderError(pub String);

impl From<tera::Error> for RenderError {
    fn from(e: tera::Error) -> Self { RenderError(e.to_string()) }
}

/// Render the full dashboard page with the subscription table
pub fn dashboard(tera: &Tera, subs: &[SubSummary]) -> Result<String, RenderError> {
    let mut ctx = Context::new();
    ctx.insert("subs", subs);
    Ok(tera.render("dashboard.html", &ctx)?)
}

/// Render just the subscription list fragment
/// Useful for htmx swap after subscribe or unsubscribe
pub fn subs_list(tera: &Tera, subs: &[SubSummary]) -> Result<String, RenderError> {
    let mut ctx = Context::new();
    ctx.insert("subs", subs);
    Ok(tera.render("subs_list.html", &ctx)?)
}

pub fn assignment_page(tera: &Tera, assignment_id: &str, rows: &[SubmissionRow]) -> Result<String, RenderError> {
    let mut ctx = Context::new();
    ctx.insert("assignment_id", &assignment_id);
    ctx.insert("rows", rows);
    Ok(tera.render("assignment.html", &ctx)?)
}


/* Full page: recent submissions list */
pub fn submissions_page(tera: &Tera, rows: &[SubmissionRow]) -> Result<String, RenderError> {
    let mut ctx = Context::new();
    ctx.insert("rows", rows);
    Ok(tera.render("submissions.html", &ctx)?)
}

/* Full page: one submission detail with artifacts */
pub fn submission_detail_page(
    tera: &Tera,
    id: &str,
    info: &SubmissionDetail,
    logs: &[LogRow],
) -> Result<String, RenderError> {
    let mut ctx = Context::new();
    ctx.insert("id", &id);
    ctx.insert("info", info);
    ctx.insert("logs", logs);
    Ok(tera.render("submission_detail.html", &ctx)?)
}


pub fn login_page(tera: &Tera) -> Result<String, RenderError> {
    let ctx = Context::new();
    Ok(tera.render("login.html", &ctx)?)
}