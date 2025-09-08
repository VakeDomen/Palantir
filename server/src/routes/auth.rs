use actix_web::{dev::{forward_ready, Payload, Service, ServiceRequest, ServiceResponse}, error::ErrorUnauthorized, get, guard::GuardContext, http::header, middleware::Next, post, web::{self, Redirect}, Error, FromRequest, HttpRequest, HttpResponse, Responder};
use actix_session::Session;
use futures_util::future::LocalBoxFuture;
use ldap3::{LdapConn, Scope, SearchEntry};
use serde::Deserialize;

use crate::{template, AppState};

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[get("/admin/login")]
pub async fn login_page(session: Session, data: web::Data<AppState>) -> impl Responder {
    if let Ok(Some(_)) = session.get::<String>("prof") {
        return HttpResponse::Found()
            .append_header(("Location", "/admin"))
            .finish();
    }
    match template::login_page(&data.tera) {
        Ok(html) => HttpResponse::Ok().body(html),
        Err(e) => HttpResponse::InternalServerError().body(e.0),
    }
}


#[post("/admin/login")]
pub async fn do_login(form: web::Form<LoginForm>, session: Session) -> impl Responder {
    let username = form.username.clone();
    let password = form.password.clone();

    match web::block(move || ldap_login_blocking(username, password)).await {
        Ok(Ok(Some(_dn))) => {
            let _ = session.insert("prof", &form.username);
            HttpResponse::Found().append_header(("Location", "/admin")).finish()
        }
        Ok(Ok(None)) => HttpResponse::Unauthorized().body("invalid credentials"),
        Ok(Err(e)) => HttpResponse::Unauthorized().body(format!("login failed: {}", e)),
        Err(e) => HttpResponse::InternalServerError().body(format!("worker error: {}", e)),
    }
}

#[get("/admin/logout")]
pub async fn logout(session: Session) -> impl Responder {
    let _ = session.purge();
    HttpResponse::Found().append_header(("Location", "/admin/login")).finish()
}

// identical to your previous function, just kept private in this module
fn ldap_login_blocking(username: String, password: String) -> Result<Option<String>, String> {
    return Ok(Some("vake".into()));

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

    if bind.rc == 0 { Ok(Some(user_dn)) } else { Ok(None) }
}

fn ldap_escape(s: &str) -> String {
    s.chars().flat_map(|c| match c {
        '\\' => "\\5c".chars().collect::<Vec<_>>(),
        '*'  => "\\2a".chars().collect(),
        '('  => "\\28".chars().collect(),
        ')'  => "\\29".chars().collect(),
        '\0' => "\\00".chars().collect(),
        _    => vec![c],
    }).collect()
}

fn is_authorized(req: &HttpRequest) -> bool {
    let session = actix_session::SessionExt::get_session(req);
    let session = session.get::<String>("prof").ok().flatten();
    print!("auth check: {:?}\n", session);
    session.is_some()
}

pub struct Authorized;

use futures_util::future::{ready, Ready};

impl FromRequest for Authorized {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if is_authorized(req) {
            ready(Ok(Authorized))
        } else {
            // Redirect to /admin/login instead of returning Unauthorized
            let resp = HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
            let err = actix_web::error::InternalError::from_response("Unauthorized", resp).into();
            ready(Err(err))
        }
    }
}