use reqwest::Url;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone)]
pub struct MoodleClient {
    pub base: String,
    pub service: String, // e.g. "moodle_mobile_app" or your custom service
    http: reqwest::Client,
}

impl MoodleClient {
    pub fn new(base: String, service: String) -> Self {
        Self {
            base,
            service,
            http: reqwest::Client::new(),
        }
    }

    pub async fn get_token(&self, username: &str, password: &str) -> Result<String, String> {
        #[derive(Deserialize)]
        struct TokenResp { token: String }

        let mut url = Url::parse(&format!("{}/login/token.php", self.base))
            .map_err(|e| e.to_string())?;
        url.query_pairs_mut()
            .append_pair("service", &self.service)
            .append_pair("username", username)
            .append_pair("password", password);

        let resp = self.http.get(url).send().await.map_err(|e| e.to_string())?;
        let text = resp.text().await.map_err(|e| e.to_string())?;
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|_| format!("unexpected token response: {}", text))?;
        if let Some(tok) = v.get("token").and_then(|t| t.as_str()) {
            return Ok(tok.to_string());
        }
        let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("token error");
        Err(err.to_string())
    }

    /// Upload files to the draft area via /webservice/upload.php
    /// Returns the draft itemid that holds all uploaded files.
    pub async fn upload_to_draft(&self, token: &str, files: &[PathBuf]) -> Result<i64, String> {
        #[derive(Deserialize)]
        struct UploadItem { itemid: i64 }

        let mut itemid: Option<i64> = None;

        for (idx, path) in files.iter().enumerate() {
            let mut url = Url::parse(&format!("{}/webservice/upload.php", self.base))
                .map_err(|e| e.to_string())?;
            {
                let mut qp = url.query_pairs_mut();
                qp.append_pair("token", token);
                if let Some(id) = itemid {
                    qp.append_pair("itemid", &id.to_string());
                }
            }

            // one file per request; Moodle accepts file_1, file_2..., we will stick to file_1
            let bytes = tokio::fs::read(path).await.map_err(|e| format!("read {:?}: {}", path, e))?;
            let part = reqwest::multipart::Part::bytes(bytes)
                .file_name(path.file_name().unwrap_or_default().to_string_lossy().to_string());

            let form = reqwest::multipart::Form::new().part("file_1", part);

            let resp = self.http.post(url).multipart(form).send().await
                .map_err(|e| format!("upload {:?}: {}", path, e))?;
            let body = resp.text().await.map_err(|e| e.to_string())?;

            // Response is a JSON array with at least one object containing itemid
            let arr: serde_json::Value = serde_json::from_str(&body)
                .map_err(|_| format!("unexpected upload response: {}", body))?;

            let first = arr.get(0)
                .ok_or_else(|| format!("empty upload response: {}", body))?;
            let id = first.get("itemid")
                .and_then(|n| n.as_i64())
                .ok_or_else(|| format!("missing itemid in: {}", first))?;

            if itemid.is_none() && idx == 0 {
                itemid = Some(id);
            }
        }

        itemid.ok_or_else(|| "no itemid returned".to_string())
    }

    pub async fn save_submission(&self, token: &str, assignment_id: &str, draft_itemid: i64) -> Result<(), String> {
        // POST form to /webservice/rest/server.php
        // fields:
        //   wstoken, wsfunction=mod_assign_save_submission, moodlewsrestformat=json
        //   assignmentid=...
        //   plugindata[files_filemanager]=draft_itemid
        let url = format!("{}/webservice/rest/server.php", self.base);
        let form = [
            ("wstoken", token),
            ("wsfunction", "mod_assign_save_submission"),
            ("moodlewsrestformat", "json"),
            ("assignmentid", assignment_id),
            ("plugindata[files_filemanager]", &draft_itemid.to_string()),
        ];

        let resp = self.http.post(url).form(&form).send().await
            .map_err(|e| e.to_string())?;
        let text = resp.text().await.map_err(|e| e.to_string())?;
        check_ws_ok(&text, "save_submission")
    }

    pub async fn submit_for_grading(&self, token: &str, assignment_id: &str) -> Result<(), String> {
        let url = format!("{}/webservice/rest/server.php", self.base);
        let form = [
            ("wstoken", token),
            ("wsfunction", "mod_assign_submit_for_grading"),
            ("moodlewsrestformat", "json"),
            ("assignmentid", assignment_id),
        ];

        let resp = self.http.post(url).form(&form).send().await
            .map_err(|e| e.to_string())?;
        let text = resp.text().await.map_err(|e| e.to_string())?;
        check_ws_ok(&text, "submit_for_grading")
    }
}

fn check_ws_ok(body: &str, ctx: &str) -> Result<(), String> {
    // Moodle WS success often returns {}, or {"status":true}, or some struct without "exception".
    // Failures include {"exception":"moodle_exception", "message":"..."}
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| format!("{}: unexpected response: {}", ctx, body))?;

    if v.get("exception").is_some() {
        let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("error");
        return Err(format!("{}: {}", ctx, msg));
    }
    Ok(())
}

async fn moodle_lookup_cmid(base: &str, token: &str, cmid: &str) -> Result<(String, String), String> {
    // GET/POST both work; we’ll POST form data as you do elsewhere
    let url = format!("{}/webservice/rest/server.php", base);
    let form = [
        ("wstoken", token),
        ("wsfunction", "core_course_get_course_module"),
        ("moodlewsrestformat", "json"),
        ("cmid", cmid),
    ];

    let resp = reqwest::Client::new()
        .post(url)
        .form(&form)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let text = resp.text().await.map_err(|e| e.to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| format!("unexpected response: {}", text))?;

    if let Some(ex) = v.get("exception") {
        let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("error");
        return Err(format!("{}: {}", ex, msg));
    }

    let cm = v.get("cm").ok_or_else(|| format!("no cm in response: {}", text))?;
    let modname = cm.get("modname").and_then(|x| x.as_str()).unwrap_or("");
    if modname != "assign" {
        return Err(format!("module is '{}', not an assignment", modname));
    }

    let instance = cm
        .get("instance")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| "missing instance id".to_string())?
        .to_string();

    let name = cm
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("Assignment")
        .to_string();

    Ok((instance, name))
}