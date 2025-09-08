use actix_files::NamedFile;
use actix_web::{get, web};
use crate::{routes::auth::Authorized, AppState};

#[get("/uploads/{filename}")]
pub async fn get_upload(
    _: Authorized,
    data: web::Data<AppState>, 
    path: web::Path<String>
) -> actix_web::Result<NamedFile> {
    let f = data.processed_dir.join(path.into_inner());
    Ok(NamedFile::open(f)?)
}
