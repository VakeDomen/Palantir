use actix_web::{get, web, HttpResponse, Responder};
use rusqlite::params;

use crate::{routes::auth::Authorized, AppState};


#[get("/admin/assignment/{aid}/stats_domains")]
pub async fn stats_domains(
    _: Authorized,
    data: web::Data<AppState>, 
    path: web::Path<String>
) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();
    let mut stmt = conn.prepare(
        "SELECT f.value FROM findings f
           JOIN submissions s ON s.id=f.submission_ref
         WHERE s.submission_id = ?1 AND f.key='top_domain'"
    ).unwrap();
    let rows = stmt.query_map(params![&aid], |r| r.get::<_, String>(0)).unwrap();
    use std::collections::HashMap;
    let mut map: HashMap<String, i64> = HashMap::new();
    for r in rows {
        if let Ok(v) = r {
            if let Some((dom, cnt)) = v.split_once(':') {
                let n = cnt.parse::<i64>().unwrap_or(1);
                *map.entry(dom.to_string()).or_default() += n;
            }
        }
    }
    let mut top: Vec<(String, i64)> = map.into_iter().collect();

    if top.is_empty() {
        return HttpResponse::Ok().finish();
    }


    top.sort_by(|a,b| b.1.cmp(&a.1));
    top.truncate(20);

    let domains: Vec<String> = top.iter().map(|x| x.0.clone()).collect();
    let counts: Vec<i64> = top.iter().map(|x| x.1).collect();

    let domains_json = serde_json::to_string(&domains).unwrap();
    let hits_json    = serde_json::to_string(&counts).unwrap();

    let mut ctx = tera::Context::new();
    ctx.insert("aid", &aid);

    // needed for the favicon <img> loop
    ctx.insert("domains", &domains);

    // needed for inline JS chart
    ctx.insert("domains_json", &domains_json);
    ctx.insert("hits_json", &hits_json);

    let html = data.tera.render("assignment/stats_domains.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)

}