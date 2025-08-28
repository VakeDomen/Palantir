use tera::{Context, Tera};
use time::{format_description::{self, well_known::Rfc3339}, OffsetDateTime, UtcOffset};


use crate::db::{FindingRow, LogRow, SubSummary, SubmissionDetail, SubmissionRow};

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


pub fn assignment_cards_page(
    tera: &Tera,
    assignment_id: &str,
    cards: &[SubmissionCard],
) -> Result<String, RenderError> {
    let mut ctx = Context::new();
    ctx.insert("assignment_id", &assignment_id);
    ctx.insert("cards", &cards);
    Ok(tera.render("assignment.html", &ctx)?)
}
#[derive(serde::Serialize)]
pub struct SubmissionCard {
    pub id: String,
    pub student_name: String,
    pub created_at: String,
    pub created_at_pretty: String,
    pub status: String,
    pub f: std::collections::HashMap<String, String>,

    pub first_ts_pretty: Option<String>,
    pub last_ts_pretty: Option<String>,
    pub duration_minutes: Option<i64>,   // <—
    pub had_browser: bool,               // <—
    pub num_web_requests: Option<i64>,   // <—
    pub max_severity: String,
}


pub fn build_cards(rows: &[SubmissionRow], findings: &[FindingRow]) -> Vec<SubmissionCard> {
    use std::collections::HashMap;

    let mut by_sub: HashMap<&str, Vec<&FindingRow>> = HashMap::new();
    for f in findings { by_sub.entry(&f.submission_ref).or_default().push(f); }

    fn sev_rank(s: &str) -> u8 { match s { "critical" => 3, "warn" => 2, _ => 1 } }

    rows.iter().map(|r| {
        let mut fkv: HashMap<String, String> = HashMap::new();
        let mut max_sev = "info".to_string();

        let mut had_browser = false;
        if let Some(fs) = by_sub.get(r.id.as_str()) {
            for f in fs {
                fkv.entry(f.key.clone()).or_insert_with(|| f.value.clone());
                if sev_rank(&f.severity) > sev_rank(&max_sev) {
                    max_sev = f.severity.clone();
                }

                if f.key.eq("had_browser") {
                    had_browser = f.value.parse().unwrap_or(false)
                }
            }
        }

        // pretty timestamps
        let first_pretty = fkv.get("first_ts").map(|s| pretty_rfc3339(s));
        let last_pretty  = fkv.get("last_ts").map(|s| pretty_rfc3339(s));

        // duration minutes
        let duration_minutes = match (fkv.get("first_ts").and_then(|s| parse_rfc3339(s)),
                                      fkv.get("last_ts").and_then(|s| parse_rfc3339(s))) {
            (Some(a), Some(b)) => Some(((b - a).whole_minutes()).max(0)),
            _ => None
        };

        // number of web requests
        let num_web_requests = fkv.get("total_net_events")
            .and_then(|s| s.parse::<i64>().ok());

        SubmissionCard {
            id: r.id.clone(),
            student_name: r.student_name.clone(),
            created_at: r.created_at.clone(),
            created_at_pretty: pretty_rfc3339(&r.created_at),
            status: r.status.clone(),
            f: fkv,
            first_ts_pretty: first_pretty,
            last_ts_pretty: last_pretty,
            duration_minutes,
            had_browser,
            num_web_requests,
            max_severity: max_sev,
        }
    }).collect()
}

fn pretty_rfc3339(s: &str) -> String {
    // fall back to raw string on any error
    let Ok(dt) = OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) else {
        return s.to_string();
    };
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let local = dt.to_offset(offset);
    // Example: "Aug 27, 2025 18:59"
    let fmt = format_description::parse("[month repr:short] [day], [year] [hour]:[minute]").unwrap();
    local.format(&fmt).unwrap_or_else(|_| s.to_string())
}

fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}