use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use rusqlite::types::Value;
use url::form_urlencoded;
use serde::Deserialize;

use crate::{db::list_findings_for_submissions, routes::admin::util::consts::{ALLOWED_KEYS_BOOL, ALLOWED_KEYS_NUM, ALLOWED_OPS}, template, AppState};

#[derive(Debug)]
struct CardQuery {
    q: Option<String>,
    filters: Vec<FilterItem>,
}

#[derive(Deserialize, Debug, Clone)]
struct FilterItem {
    key: String,
    op: String,
    #[serde(default)]
    val: Option<String>, // allow "exists"
}

fn parse_card_query(req: &HttpRequest) -> CardQuery {
    let mut q: Option<String> = None;
    let mut filters: Vec<FilterItem> = Vec::new();

    for (k, v) in form_urlencoded::parse(req.query_string().as_bytes()) {
        match k.as_ref() {
            "q" => {
                let t = v.trim().to_string();
                if !t.is_empty() { q = Some(t); }
            }
            "filters" | "filters[]" => {
                match serde_json::from_str::<FilterItem>(&v) {
                    Ok(f) => filters.push(f),
                    Err(e) => log::warn!("bad filter JSON '{}': {}", v, e),
                }
            }
            _ => {}
        }
    }

    CardQuery { q, filters }
}

fn build_where_for_filters(
    qb: &mut String,
    args: &mut Vec<rusqlite::types::Value>,
    filters: &[FilterItem],
) {
    use rusqlite::types::Value;

    for f in filters {
        if !ALLOWED_OPS.contains(&f.op.as_str()) { continue; }

        if ALLOWED_KEYS_NUM.contains(&f.key.as_str()) {
            let cast = "CAST(f.value AS INTEGER)";
            let cmp = match f.op.as_str() {
                "gt" => ">", "ge" => ">=", "eq" => "=", "le" => "<=", "lt" => "<", "ne" => "!=",
                "exists" => {
                    qb.push_str(
                        " AND EXISTS (SELECT 1 FROM findings f
                           WHERE f.submission_ref = s.id AND f.key = ? AND f.value GLOB '[0-9]*')"
                    );
                    args.push(f.key.clone().into());
                    continue;
                }
                _ => continue,
            };

            qb.push_str(&format!(
                " AND EXISTS (SELECT 1 FROM findings f
                   WHERE f.submission_ref = s.id AND f.key = ?
                     AND f.value GLOB '[0-9]*' AND {cast} {cmp} ?)"
            ));

            args.push(f.key.clone().into());
            let v: i64 = f.val.as_deref().unwrap_or("0").parse().unwrap_or(0);
            args.push(v.into());

        } else if ALLOWED_KEYS_BOOL.contains(&f.key.as_str()) {
            if f.op == "exists" {
                qb.push_str(" AND EXISTS (SELECT 1 FROM findings f WHERE f.submission_ref = s.id AND f.key = ?)");
                args.push(f.key.clone().into());
            } else if matches!(f.op.as_str(), "eq" | "ne") {
                let want = matches!(f.val.as_deref().unwrap_or("false").to_ascii_lowercase().as_str(), "true" | "1" | "yes");
                let cmp = if f.op == "eq" { "=" } else { "!=" };
                qb.push_str(&format!(
                    " AND EXISTS (SELECT 1 FROM findings f
                       WHERE f.submission_ref = s.id AND f.key = ? AND lower(f.value) {cmp} ?)"
                ));
                args.push(f.key.clone().into());
                args.push(Value::Text(if want { "true".into() } else { "false".into() }));
            }
        }
    }
}

#[get("/admin/assignment/{aid}/cards")]
pub async fn assignment_cards(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    let aid = path.into_inner();
    let cq = parse_card_query(&req);
    log::debug!("CardQuery parsed: {:?}", cq);

    // base query
    let mut sql = String::from(
        "SELECT s.id, s.student_name, s.created_at, s.status
           FROM submissions s
          WHERE s.submission_id = ?"
    );
    let mut args: Vec<rusqlite::types::Value> = vec![aid.clone().into()];

    if let Some(q) = cq.q.as_ref() {
        sql.push_str(" AND s.student_name LIKE ?");
        args.push(format!("%{}%", q).into());
    }

    build_where_for_filters(&mut sql, &mut args, &cq.filters);
    sql.push_str(" ORDER BY s.created_at DESC LIMIT 300");

    // DB fetch
    let conn = match data.pool.get() {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| {
        Ok(crate::db::SubmissionRow {
            id: r.get(0)?, student_name: r.get(1)?, created_at: r.get(2)?, status: r.get(3)?,
        })
    });

    let mut subs = Vec::new();
    if let Ok(it) = rows {
        for row in it {
            if let Ok(s) = row { subs.push(s); }
        }
    }

    // findings + cards
    let ids: Vec<String> = subs.iter().map(|s| s.id.clone()).collect();
    let findings = match list_findings_for_submissions(&data.pool, &ids) {
        Ok(v) => v, Err(e) => return HttpResponse::InternalServerError().body(e),
    };
    let cards = template::build_cards(&subs, &findings);
    // render
    let mut ctx = tera::Context::new();
    ctx.insert("cards", &cards);
    match data.tera.render("assignment/card_list.html", &ctx) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}



fn pretty_filter_tag(f: &FilterItem) -> String {
    let op = match f.op.as_str() {
        "gt" => ">", "ge" => "≥", "eq" => "=", "le" => "≤", "lt" => "<", "ne" => "≠",
        "exists" => "exists",
        x => x,
    };
    if f.op == "exists" {
        format!("{} {}", f.key, op)
    } else {
        format!("{} {} {}", f.key, op, f.val.as_deref().unwrap_or(""))
    }
}

#[get("/admin/assignment/{aid}/table_rows")]
pub async fn assignment_table_rows(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    let aid = path.into_inner();
    let cq = parse_card_query(&req);

    let mut sql = String::from(
        "SELECT s.id, s.student_name, s.created_at, s.status
           FROM submissions s
          WHERE s.submission_id = ?"
    );
    let mut args: Vec<Value> = vec![aid.clone().into()];

    if let Some(q) = cq.q.as_ref().filter(|s| !s.trim().is_empty()) {
        sql.push_str(" AND s.student_name LIKE ?");
        args.push(format!("%{}%", q).into());
    }

    build_where_for_filters(&mut sql, &mut args, &cq.filters);
    sql.push_str(" ORDER BY s.created_at DESC LIMIT 300");

    // DB
    let conn = match data.pool.get() {
        Ok(c) => c, Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s, Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| {
        Ok(crate::db::SubmissionRow {
            id: r.get(0)?, student_name: r.get(1)?, created_at: r.get(2)?, status: r.get(3)?,
        })
    });

    let mut subs = Vec::new();
    if let Ok(it) = rows {
        for row in it {
            if let Ok(s) = row { subs.push(s); }
        }
    }

    // findings + cards (reusing your builder)
    let ids: Vec<String> = subs.iter().map(|s| s.id.clone()).collect();
    let findings = match list_findings_for_submissions(&data.pool, &ids) {
        Ok(v) => v, Err(e) => return HttpResponse::InternalServerError().body(e),
    };
    let cards = template::build_cards(&subs, &findings);

    // pretty tags for the *active filters* (shared)
    let filter_tags: Vec<String> = cq.filters.iter().map(pretty_filter_tag).collect();

    // render rows only
    let mut ctx = tera::Context::new();
    ctx.insert("cards", &cards);
    ctx.insert("filter_tags", &filter_tags);
    let html = match data.tera.render("assignment/table_rows.html", &ctx) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };
    HttpResponse::Ok().body(html)
}


#[get("/admin/assignment/{aid}/table")]
pub async fn assignment_table_page(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    let aid = path.into_inner();
    // You can also parse filters here and pass `active_filters` to show at top
    let cq = parse_card_query(&req);
    let pretty: Vec<String> = cq.filters.iter().map(pretty_filter_tag).collect();

    let mut ctx = tera::Context::new();
    ctx.insert("assignment_id", &aid);
    ctx.insert("active_filters", &pretty);
    match data.tera.render("assignment/table.html", &ctx) {
        Ok(h) => HttpResponse::Ok().body(h),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
