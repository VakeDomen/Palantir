use actix_session::{config::CookieContentSecurity, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, App, HttpServer, web};
use once_cell::sync::Lazy;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::{env, fs, path::PathBuf};
use tera::Tera;

mod db;
mod upload_processing;
mod routes;
mod template;

use routes::{auth, admin, api, files};

use crate::routes::traffic_outliers;

static COOKIE_KEY: Lazy<Key> = Lazy::new(|| {
    let hex_key = env::var("COOKIE_KEY_HEX").expect("COOKIE_KEY_HEX not set");
    let bytes = hex::decode(hex_key).expect("invalid COOKIE_KEY_HEX");
    Key::from(bytes.as_slice())
});

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<SqliteConnectionManager>,
    pub upload_dir: PathBuf,
    pub processed_dir: PathBuf,
    pub tera: Tera,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = dotenv::dotenv();

    let host = env::var("APP_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = env::var("APP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let db_path = env::var("SQLITE_PATH").unwrap_or_else(|_| "data/palantir.db".to_string());
    let upload_dir_env = env::var("UPLOAD_DIR").unwrap_or_else(|_| "uploads".to_string());
    let upload_dir_abs = {
        let p = PathBuf::from(&upload_dir_env);
        if p.is_absolute() { p } else { std::env::current_dir().unwrap().join(p) }
    };
    let processed_dir = std::env::current_dir().unwrap().join("processed_uploads");

    fs::create_dir_all(&upload_dir_abs).ok();
    fs::create_dir_all(&processed_dir).ok();

    // load templates from ./templates
    // in production you might want to embed; for now load from disk
    let tera = Tera::new("templates/**/*").expect("load templates");

    let pool = db::init_db(&db_path);
    let data = web::Data::new(AppState {
        pool,
        upload_dir: upload_dir_abs.clone(),
        processed_dir: processed_dir.clone(),
        tera,
    });

    // background worker without tokio dependencies
    {
        let data_clone = data.clone();
        std::thread::spawn(move || {
            loop {
                if let Err(e) = upload_processing::process_pending(&data_clone) {
                    eprintln!("processor error: {e}");
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        });
    }

    println!("Rrunning server...");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .wrap(SessionMiddleware::builder(CookieSessionStore::default(), COOKIE_KEY.clone())
                .cookie_secure(false)
                .cookie_content_security(CookieContentSecurity::Private)
                .build())
            .service(actix_files::Files::new("/static", ".").show_files_listing())
            .service(auth::login_page)
            .service(auth::do_login)
            .service(auth::logout)
            .service(admin::dashboard)
            .service(admin::assignment_page)
            .service(admin::submissions)
            .service(admin::submission_detail)
            .service(admin::subscribe)
            .service(admin::unsubscribe)
            .service(api::upload_logs)
            .service(files::get_upload)
            .service(admin::net_timeline_json)
            .service(admin::net_timeline_fragment)
            .service(admin::proc_timeline_json)
            .service(admin::proc_timeline_fragment)
            .service(admin::stats_activity)
            .service(admin::stats_status)
            .service(admin::stats_duration)
            .service(admin::stats_browser)
            .service(admin::stats_domains)
            // .service(admin::stats_outliers)
            .service(traffic_outliers::stats_outliers)
            .service(admin::stats_shared_lan)
    })
    .bind((host, port))?
    .run()
    .await
}
