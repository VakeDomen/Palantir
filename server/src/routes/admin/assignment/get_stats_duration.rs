use actix_web::{get, web, HttpResponse, Responder};

use crate::{db::fetch_durations_minutes, routes::auth::Authorized, AppState};

#[get("/admin/assignment/{aid}/stats_duration")]
pub async fn stats_duration(
    _: Authorized,
    data: web::Data<AppState>, 
    path: web::Path<String>
) -> impl Responder {
    let aid = path.into_inner();
    let conn = data.pool.get().unwrap();
    let vals = fetch_durations_minutes(&conn, &aid);

    let mut avg_display = String::from("N/A");
    let mut max_display = String::from("N/A");
    let mut min_display = String::from("N/A");
    if !vals.is_empty() {
        if let Some(max_time) = vals.iter().max() {
            max_display = to_display_time(max_time);
        };

        if let Some(min_time) = vals.iter().min() {
            min_display = to_display_time(min_time);
        };
        

        let sum: i64 = vals
            .iter()
            .sum();

        let avg = sum as f64 / vals.len() as f64;
        let avg = avg.round() as i64;
        let avg = avg as i64;

        avg_display = to_display_time(&avg);
    }

    let mut ctx = tera::Context::new();

    ctx.insert("aid", &aid);
    ctx.insert("count", &vals.len());
    ctx.insert("avg", &avg_display);
    ctx.insert("max", &max_display);
    ctx.insert("min", &min_display);

    let html = data.tera.render("assignment/stats_duration.html", &ctx).unwrap();
    
    HttpResponse::Ok().body(html)
}

fn to_display_time(minutes: &i64) -> String {
    let minutes = *minutes;
    if minutes < 60 {
        format!("{} min", minutes)
    } else if minutes < 60 * 24 {
        let hours = minutes as f64 / 60.0;
        format!("{:.1} hr", hours)
    } else {
        let days = minutes as f64 / (60.0 * 24.0);
        format!("{:.1} days", days)
    }
}