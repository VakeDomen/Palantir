use actix_multipart::Multipart;
use actix_web::{post, web, Error, HttpResponse};
use futures_util::StreamExt as _;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use std::fs;
use crate::AppState;
use crate::db; 


#[derive(serde::Serialize)]
pub struct ApiReceipt { pub receipt_id: String }

#[derive(serde::Deserialize)]
pub struct LogMeta {
    pub submission_id: String,
    pub student_name: String,
    pub moodle_assignment_id: Option<String>,
    pub client_version: Option<String>,
}

#[post("/api/v1/logs")]
pub async fn upload_logs(
    data: web::Data<AppState>,
    mut payload: Multipart,
    query: web::Query<LogMeta>,
) -> Result<HttpResponse, Error> {
    let meta = query.into_inner();
    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    // 1 create submission row via db layer
    let sub_id = db::new_submission(
        &data.pool,
        &meta.submission_id,
        &meta.student_name,
        &now,
        meta.moodle_assignment_id.as_deref().unwrap_or(""),
        meta.client_version.as_deref().unwrap_or("client"),
    ).map_err(actix_web::error::ErrorInternalServerError)?;

    // 2 stream-upload file to disk, compute sha256 and size
    let mut saved_path = None;
    let mut sha256 = Sha256::new();
    let mut total: i64 = 0;

    while let Some(item) = payload.next().await {
        let mut field = item?;
        let cd = field.content_disposition().clone();
        let name = cd.get_name().unwrap_or("");
        if name != "log_zip" {
            while let Some(chunk) = field.next().await { let _ = chunk?; }
            continue;
        }

        let filename = format!(
            "{}-{}-{}.zip",
            now.replace(':', "_"),
            meta.submission_id,
            meta.student_name.replace(' ', "_")
        );
        let dest = data.upload_dir.join(filename);
        let mut f = fs::File::create(&dest)?;

        while let Some(chunk) = field.next().await {
            let bytes = chunk?;
            sha256.update(&bytes);
            total += bytes.len() as i64;
            use std::io::Write;
            f.write_all(&bytes)?;
        }
        saved_path = Some(dest);
    }

    // 3 persist artifact row
    let sum_hex = hex::encode(sha256.finalize());
    if let Some(path) = saved_path {
        db::add_log_artifact(
            &data.pool,
            &sub_id,
            &path.to_string_lossy(),
            &sum_hex,
            total,
        ).map_err(actix_web::error::ErrorInternalServerError)?;
    }

    Ok(HttpResponse::Ok().json(ApiReceipt { receipt_id: sub_id }))
}
