use std::{fs::File, path::{Path, PathBuf}};

use rusqlite::params;
use zip::ZipArchive;

// helper that opens the processed zip by file name
pub fn open_processed_zip_by_submission(
    data: &crate::AppState,
    submission_id: &str
) -> Result<ZipArchive<File>, String> {
    let conn = data.pool.get().map_err(|e| e.to_string())?;
    let full: String = conn.query_row(
        "SELECT fs_path FROM logs WHERE submission_ref = ?1 ORDER BY rowid ASC LIMIT 1",
        params![&submission_id],
        |r| r.get(0),
    ).map_err(|e| e.to_string())?;
    let fname = Path::new(&full).file_name().ok_or("bad file name")?;
    let zip_path: PathBuf = data.processed_dir.join(fname);
    let file = File::open(&zip_path).map_err(|e| format!("open {}: {}", zip_path.display(), e))?;
    ZipArchive::new(file).map_err(|e| format!("zip: {e}"))
}