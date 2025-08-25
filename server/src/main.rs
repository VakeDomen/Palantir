use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_session::{config::CookieContentSecurity, storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, get, post, web, App, Error, HttpResponse, HttpServer, Responder};
use futures_util::StreamExt as _;
use ldap3::{LdapConn, Scope, SearchEntry};
use once_cell::sync::Lazy;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Write, path::PathBuf};
use time::OffsetDateTime;
use uuid::Uuid;
use dotenv;

static COOKIE_KEY: Lazy<Key> = Lazy::new(|| {
    let hex_key = env::var("COOKIE_KEY_HEX").expect("COOKIE_KEY_HEX not set");
    let bytes = hex::decode(hex_key).expect("invalid COOKIE_KEY_HEX");
    Key::from(bytes.as_slice())
});

#[derive(Clone)]
struct AppState {
    pool: Pool<SqliteConnectionManager>,
    upload_dir: PathBuf,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct ApiReceipt {
    receipt_id: String,
}

#[derive(Deserialize)]
struct LogMeta {
    submission_id: String,
    student_name: String,
    moodle_assignment_id: Option<String>,
    client_version: Option<String>,
}

fn init_db(path: &str) -> Pool<SqliteConnectionManager> {
    let manager = SqliteConnectionManager::file(path);
    let pool = Pool::new(manager).expect("db pool");
    {
        let conn = pool.get().expect("conn");
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS submissions(
              id TEXT PRIMARY KEY,
              submission_id TEXT NOT NULL,
              student_name TEXT NOT NULL,
              created_at TEXT NOT NULL,
              moodle_assignment_id TEXT,
              client_version TEXT,
              status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS logs(
              id TEXT PRIMARY KEY,
              submission_ref TEXT NOT NULL,
              fs_path TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              size_bytes INTEGER NOT NULL,
              FOREIGN KEY(submission_ref) REFERENCES submissions(id)
            );
            CREATE TABLE IF NOT EXISTS findings(
              id TEXT PRIMARY KEY,
              submission_ref TEXT NOT NULL,
              kind TEXT NOT NULL,
              key TEXT NOT NULL,
              value TEXT NOT NULL,
              severity TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(submission_ref) REFERENCES submissions(id)
            );
            "#,
        )
        .expect("migrations");
    }
    pool
}

#[get("/admin/login")]
async fn login_page(session: Session) -> impl Responder {
    if let Ok(Some(_)) = session.get::<String>("prof") {
        return actix_web::HttpResponse::Found()
            .append_header(("Location", "/admin/submissions"))
            .finish();
    }
    let html = r#"
    <html>
      <head>
        <meta charset="utf-8">
        <title>Palantir admin login</title>
      </head>
      <body>
        <h2>Professor login</h2>
        <form method="post" action="/admin/login">
          <label>Username <input type="text" name="username"></label><br>
          <label>Password <input type="password" name="password"></label><br>
          <button type="submit">Sign in</button>
        </form>
      </body>
    </html>
    "#;
    HttpResponse::Ok().body(html)
}

#[post("/admin/login")]
async fn do_login(form: web::Form<LoginForm>, session: Session) -> impl Responder {
    let username = form.username.clone();
    let password = form.password.clone();

    match web::block(move || ldap_login_blocking(username, password)).await {
        Ok(Ok(Some(_dn))) => {
            let _ = session.insert("prof", &form.username);
            actix_web::HttpResponse::Found()
                .append_header(("Location", "/admin/submissions"))
                .finish()
        }
        Ok(Ok(None)) => HttpResponse::Unauthorized().body("invalid credentials"),
        Ok(Err(e)) => HttpResponse::Unauthorized().body(format!("login failed: {}", e)),
        Err(e) => HttpResponse::InternalServerError().body(format!("worker error: {}", e)),
    }
}


fn ldap_login_blocking(username: String, password: String) -> Result<Option<String>, String> {
    let server   = std::env::var("LDAP_SERVER").map_err(|_| "LDAP_SERVER not set".to_string())?;
    let base_dn  = std::env::var("LDAP_BASE_DN").unwrap_or_else(|_| "dc=example,dc=org".to_string());
    let user_attr= std::env::var("LDAP_USER_ATTR").unwrap_or_else(|_| "uid".to_string());
    let bind_dn  = std::env::var("LDAP_BIND_DN").ok();
    let bind_pw  = std::env::var("LDAP_BIND_PASSWORD").ok();

    let mut ldap = LdapConn::new(&server).map_err(|e| e.to_string())?;

    if let (Some(dn), Some(pw)) = (bind_dn.as_deref(), bind_pw.as_deref()) {
        ldap.simple_bind(dn, pw).map_err(|e| e.to_string())?
            .success().map_err(|e| format!("{:?}", e))?;
    }

    let filter = format!("({}={})", user_attr, ldap_escape(&username));
    let (rs, _res) = ldap
        .search(&base_dn, Scope::Subtree, &filter, vec!["cn", "sn", "mail"])
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("{:?}", e))?;

    let first = match rs.into_iter().next() {
        Some(e) => e,
        None => {
            let _ = ldap.unbind();
            return Ok(None);
        }
    };

    let entry = SearchEntry::construct(first);
    let user_dn = entry.dn;

    let bind = ldap.simple_bind(&user_dn, &password).map_err(|e| e.to_string())?;
    let _ = ldap.unbind();

    if bind.rc == 0 {
        Ok(Some(user_dn))
    } else {
        Ok(None)
    }
}

fn ldap_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => "\\5c".chars().collect::<Vec<_>>(),
            '*'  => "\\2a".chars().collect(),
            '('  => "\\28".chars().collect(),
            ')'  => "\\29".chars().collect(),
            '\0' => "\\00".chars().collect(),
            _    => vec![c],
        })
        .collect()
}

#[get("/admin/logout")]
async fn logout(session: Session) -> impl Responder {
    let _ = session.purge();
    actix_web::HttpResponse::Found()
        .append_header(("Location", "/admin/login"))
        .finish()
}

#[get("/admin/submissions")]
async fn submissions(session: Session, data: web::Data<AppState>) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return actix_web::HttpResponse::Found()
            .append_header(("Location", "/admin/login"))
            .finish();
    }
    let conn = data.pool.get().expect("db");
    let mut stmt = conn
        .prepare("SELECT id, submission_id, student_name, created_at, status FROM submissions ORDER BY created_at DESC LIMIT 100")
        .unwrap();
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .unwrap();

    let mut html = String::from(
        r#"<html><head><meta charset="utf-8"><title>Palantir submissions</title>
           <script src="https://unpkg.com/htmx.org@1.9.12"></script>
           </head><body><h2>Submissions</h2><a href="/admin/logout">Logout</a>
           <table border="1" cellpadding="6"><tr><th>id</th><th>submission</th><th>student</th><th>time</th><th>status</th></tr>"#,
    );
    for r in rows {
        let (id, sid, user, ts, status) = r.unwrap();
        html.push_str(&format!(
            r#"<tr>
                <td><a href="/admin/submissions/{}">{}</a></td>
                <td>{}</td><td>{}</td><td>{}</td><td>{}</td>
               </tr>"#,
            id, id, sid, user, ts, status
        ));
    }
    html.push_str("</table></body></html>");
    HttpResponse::Ok().body(html)
}

#[get("/admin/submissions/{id}")]
async fn submission_detail(
    session: Session,
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if session.get::<String>("prof").ok().flatten().is_none() {
        return actix_web::HttpResponse::Found()
            .append_header(("Location", "/admin/login"))
            .finish();
    }
    let id = path.into_inner();
    let conn = data.pool.get().expect("db");

    let mut html = String::new();
    let mut stmt = conn
        .prepare("SELECT submission_id, student_name, created_at, status FROM submissions WHERE id = ?1")
        .unwrap();
    let row = stmt.query_row(params![&id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    });

    match row {
        Ok((sid, student, ts, status)) => {
            html.push_str("<html><head><meta charset=\"utf-8\"><title>Submission</title></head><body>");
            html.push_str(&format!(
                "<h2>Submission {}</h2><p>assignment {} by {} at {} status {}</p>",
                id, sid, student, ts, status
            ));
            // show log file if present
            let mut lst = conn
                .prepare("SELECT fs_path, sha256, size_bytes FROM logs WHERE submission_ref = ?1")
                .unwrap();
            let entries = lst
                .query_map(params![&id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap();
            html.push_str("<h3>Artifacts</h3><ul>");
            for e in entries {
                let (path, sum, size) = e.unwrap();
                let name = path.split('/').last().unwrap_or(&path);
                html.push_str(&format!(
                    "<li>{} sha256 {} size {} bytes</li>",
                    name, sum, size
                ));
            }
            html.push_str("</ul></body></html>");
            HttpResponse::Ok().body(html)
        }
        Err(_) => HttpResponse::NotFound().body("not found"),
    }
}

#[post("/api/v1/logs")]
async fn upload_logs(
    data: web::Data<AppState>,
    mut payload: Multipart,
    query: web::Query<LogMeta>,
) -> Result<HttpResponse, Error> {
    let meta = query.into_inner();

    // create submission row
    let sub_id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap();

    {
        let conn = data.pool.get().unwrap();
        conn.execute(
            "INSERT INTO submissions(id, submission_id, student_name, created_at, moodle_assignment_id, client_version, status)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &sub_id,
                &meta.submission_id,
                &meta.student_name,
                &now,
                &meta.moodle_assignment_id.unwrap_or_default(),
                &meta.client_version.unwrap_or_else(|| "client".to_string()),
                "received"
            ],
        )
        .unwrap();
    }

    // expect a single file part named log_zip
    let mut saved_path = None;
    let mut sha256 = Sha256::new();
    let mut total: i64 = 0;

    while let Some(item) = payload.next().await {
        let mut field = item?;
        let cd = field.content_disposition().clone();
        let name = cd.get_name().unwrap_or("");
        if name != "log_zip" {
            // drain and ignore unknown fields
            while let Some(chunk) = field.next().await {
                let _ = chunk?;
            }
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
            f.write_all(&bytes)?;
        }
        saved_path = Some(dest);
    }

    let sum_hex = hex::encode(sha256.finalize());

    if let Some(path) = saved_path {
        let conn = data.pool.get().unwrap();
        conn.execute(
            "INSERT INTO logs(id, submission_ref, fs_path, sha256, size_bytes)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![Uuid::new_v4().to_string(), &sub_id, path.to_string_lossy(), sum_hex, total],
        )
        .unwrap();
    }

    Ok(HttpResponse::Ok().json(ApiReceipt {
        receipt_id: sub_id,
    }))
}

#[get("/uploads/{filename}")]
async fn get_upload(data: web::Data<AppState>, path: web::Path<String>) -> actix_web::Result<NamedFile> {
    let f = data.upload_dir.join(path.into_inner());
    Ok(NamedFile::open(f)?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = dotenv::dotenv();
    let host = env::var("APP_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = env::var("APP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let db_path = env::var("SQLITE_PATH").unwrap_or_else(|_| "data/palantir.db".to_string());
    let upload_dir = env::var("UPLOAD_DIR").unwrap_or_else(|_| "uploads".to_string());

    fs::create_dir_all(&upload_dir).ok();

    let pool = init_db(&db_path);
    let data = web::Data::new(AppState {
        pool,
        upload_dir: PathBuf::from(upload_dir),
    });

    println!("Rrunning server...");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .wrap(SessionMiddleware::builder(CookieSessionStore::default(), COOKIE_KEY.clone())
                .cookie_secure(false)
                .cookie_content_security(CookieContentSecurity::Private)
                .build())
            .service(login_page)
            .service(do_login)
            .service(logout)
            .service(submissions)
            .service(submission_detail)
            .service(upload_logs)
            .service(get_upload)
    })
    .bind((host, port))?
    .run()
    .await
}
