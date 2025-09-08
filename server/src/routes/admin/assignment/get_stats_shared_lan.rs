use std::io::BufRead;

use actix_web::{get, web, HttpResponse, Responder};
use rusqlite::params;

use crate::{routes::{admin::util::zip::open_processed_zip_by_submission, auth::Authorized}, AppState};




#[get("/admin/assignment/{aid}/stats_shared_lan")]
pub async fn stats_shared_lan(
    _: Authorized,
    data: web::Data<AppState>, 
    path: web::Path<String>
) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();

    // submissions for this assignment
    let mut q = conn.prepare("SELECT id, student_name FROM submissions WHERE submission_id = ?1").unwrap();
    let subs = q.query_map(params![&aid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap();

    use std::collections::{HashMap, HashSet};
    let mut ip_to_students: HashMap<String, HashSet<String>> = HashMap::new();

    for row in subs {
        let (sub_id, student) = row.unwrap();
        // open corresponding processed zip
        if let Ok(mut zip) = open_processed_zip_by_submission(&data, &sub_id) {
            let file_result = match zip.by_name("snapshot/palantir.log") {
                Ok(f) => f,
                Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
            };
            let mut br = std::io::BufReader::new(file_result);
            let mut line = String::new();
            while let Ok(n) = br.read_line(&mut line) {
                if n == 0 { break; }
                if !line.contains("\"kind\":\"net\"") { line.clear(); continue; }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(ip) = v.get("src_ip").and_then(|x| x.as_str()) {
                        if is_private_ip(ip) {
                            ip_to_students.entry(ip.to_string()).or_default().insert(student.clone());
                        }
                    }
                }
                line.clear();
            }
        }
    }

    // keep only IPs with more than one student
    let mut rows: Vec<(String, Vec<String>)> = ip_to_students.into_iter()
        .filter_map(|(ip, set)| {
            let v: Vec<String> = set.into_iter().collect();
            if v.len() > 1 { Some((ip, v)) } else { None }
        }).collect();

    if rows.is_empty() {
        return HttpResponse::Ok().finish();
    }


    rows.sort_by(|a,b| b.1.len().cmp(&a.1.len()));


    let mut ctx = tera::Context::new();
    ctx.insert("rows", &rows);
    let html = data.tera.render("assignment/stats_shared_lan.html", &ctx).unwrap();
    HttpResponse::Ok().body(html)
}


fn is_private_ip(ip: &str) -> bool {
    // naive private IPv4 check
    let parts: Vec<_> = ip.split('.').collect();
    if parts.len() != 4 { return false; }
    let p: Vec<i32> = parts.iter().filter_map(|s| s.parse().ok()).collect();
    if p.len() != 4 { return false; }
    (p[0] == 10)
    || (p[0] == 192 && p[1] == 168)
    || (p[0] == 172 && (16..=31).contains(&p[1]))
}
