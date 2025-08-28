use actix_files::NamedFile;
use actix_web::{get, web};
use crate::AppState;

#[get("/uploads/{filename}")]
pub async fn get_upload(data: web::Data<AppState>, path: web::Path<String>) -> actix_web::Result<NamedFile> {
    let f = data.upload_dir.join(path.into_inner());
    Ok(NamedFile::open(f)?)
}
