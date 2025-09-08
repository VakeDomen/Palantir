use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

pub fn init_db(path: &str) -> Pool<SqliteConnectionManager> {
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

            CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON submissions(submission_id);

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

              created_at TEXT NOT NULL,
              FOREIGN KEY(submission_ref) REFERENCES submissions(id)
            );

            CREATE TABLE IF NOT EXISTS subscriptions(
              prof TEXT NOT NULL,
              assignment_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(prof, assignment_id)
            );

            CREATE INDEX IF NOT EXISTS idx_subscriptions_prof ON subscriptions(prof);
            "#
        ).expect("migrations");
    }
    pool
}

/* Types for query results */

#[derive(serde::Serialize)]
pub struct SubSummary {
    pub assignment_id: String,
    pub latest_status: String,
    pub count: i64,
}

#[derive(serde::Serialize)]
pub struct SubmissionRow {
    pub id: String,
    pub student_name: String,
    pub created_at: String,
    pub status: String,
}

#[derive(serde::Serialize)]
pub struct SubmissionDetail {
    pub moodle_assignment_id: String,
    pub submission_id: String,
    pub student_name: String,
    pub created_at: String,
    pub status: String,
}

#[derive(serde::Serialize)]
pub struct LogRow {
    pub fs_path: String,
    pub sha256: String,
    pub size_bytes: i64,
}

/* Subscriptions */

pub fn list_subscription_summaries(pool: &Pool<SqliteConnectionManager>, prof: &str) -> Result<Vec<SubSummary>, String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare(
        r#"
        SELECT s.assignment_id,
               COALESCE((
                 SELECT status FROM submissions
                 WHERE submission_id = s.assignment_id
                 ORDER BY created_at DESC
                 LIMIT 1
               ), 'n/a') as latest_status,
               (SELECT COUNT(*) FROM submissions WHERE submission_id = s.assignment_id) as cnt
        FROM subscriptions s
        WHERE s.prof = ?1
        ORDER BY s.created_at DESC
        "#
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map([prof], |r| {
        Ok(SubSummary {
            assignment_id: r.get(0)?,
            latest_status: r.get(1)?,
            count: r.get::<_, i64>(2)?,
        })
    }).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows { out.push(row.map_err(|e| e.to_string())?); }
    Ok(out)
}

pub fn subscribe(pool: &Pool<SqliteConnectionManager>, prof: &str, assignment_id: &str, created_at_rfc3339: &str) -> Result<(), String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR IGNORE INTO subscriptions(prof, assignment_id, created_at) VALUES(?1, ?2, ?3)",
        params![prof, assignment_id, created_at_rfc3339],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn unsubscribe(pool: &Pool<SqliteConnectionManager>, prof: &str, assignment_id: &str) -> Result<(), String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM subscriptions WHERE prof = ?1 AND assignment_id = ?2",
        params![prof, assignment_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

/* Submissions listing and details */

pub fn list_submissions_by_assignment(pool: &Pool<SqliteConnectionManager>, assignment_id: &str) -> Result<Vec<SubmissionRow>, String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare(
        "SELECT id, student_name, created_at, status
         FROM submissions
         WHERE submission_id = ?1
         ORDER BY created_at DESC"
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map([assignment_id], |r| {
        Ok(SubmissionRow {
            id: r.get(0)?,
            student_name: r.get(1)?,
            created_at: r.get(2)?,
            status: r.get(3)?,
        })
    }).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows { out.push(row.map_err(|e| e.to_string())?); }
    Ok(out)
}

pub fn get_submission_detail(pool: &Pool<SqliteConnectionManager>, id: &str) -> Result<Option<SubmissionDetail>, String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare(
        "SELECT submission_id, student_name, created_at, status, moodle_assignment_id
         FROM submissions
         WHERE id = ?1"
    ).map_err(|e| e.to_string())?;

    let row = stmt.query_row([id], |r| {
        Ok(SubmissionDetail {
            submission_id: r.get(0)?,
            student_name: r.get(1)?,
            created_at: r.get(2)?,
            status: r.get(3)?,
            moodle_assignment_id: r.get(4)?,
        })
    }).optional().map_err(|e| e.to_string())?;

    Ok(row)
}

pub fn list_logs_for_submission(pool: &Pool<SqliteConnectionManager>, submission_id: &str) -> Result<Vec<LogRow>, String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare(
        "SELECT fs_path, sha256, size_bytes
         FROM logs
         WHERE submission_ref = ?1"
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map([submission_id], |r| {
        Ok(LogRow {
            fs_path: r.get(0)?,
            sha256: r.get(1)?,
            size_bytes: r.get(2)?,
        })
    }).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows { out.push(row.map_err(|e| e.to_string())?); }
    Ok(out)
}

/* create a new submission row and return its generated id */
pub fn new_submission(
    pool: &Pool<SqliteConnectionManager>,
    submission_id: &str,
    student_name: &str,
    created_at_rfc3339: &str,
    moodle_assignment_id: &str,
    client_version: &str,
) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let conn = pool.get().map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO submissions(id, submission_id, student_name, created_at, moodle_assignment_id, client_version, status)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'received')",
        params![
            &id,
            submission_id,
            student_name,
            created_at_rfc3339,
            moodle_assignment_id,
            client_version
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

/* add a log artifact row and return its generated id */
pub fn add_log_artifact(
    pool: &Pool<SqliteConnectionManager>,
    submission_ref: &str,
    fs_path: &str,
    sha256_hex: &str,
    size_bytes: i64,
) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let conn = pool.get().map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO logs(id, submission_ref, fs_path, sha256, size_bytes)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![&id, submission_ref, fs_path, sha256_hex, size_bytes],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}


// in src/db.rs
#[derive(serde::Serialize, Clone, Debug)]
pub struct FindingRow {
    pub submission_ref: String,
    pub kind: String,
    pub key: String,
    pub value: String,
}

/// Fetch findings for a set of submission ids
pub fn list_findings_for_submissions(
    pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    submission_ids: &[String],
) -> Result<Vec<FindingRow>, String> {
    if submission_ids.is_empty() {
        return Ok(vec![]);
    }
    // build a dynamic IN clause safely
    let placeholders = std::iter::repeat("?")
        .take(submission_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT submission_ref, kind, key, value
         FROM findings
         WHERE submission_ref IN ({})",
        placeholders
    );

    let conn = pool.get().map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;

    let params = submission_ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect::<Vec<_>>();
    let rows = stmt
        .query_map(params.as_slice(), |r| {
            Ok(FindingRow {
                submission_ref: r.get(0)?,
                kind: r.get(1)?,
                key: r.get(2)?,
                value: r.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}


pub fn fetch_durations_minutes(conn: &rusqlite::Connection, aid: &str) -> Vec<i64> {
    let mut out = Vec::new();
    let mut q = conn.prepare(
      "SELECT value FROM findings f
         JOIN submissions s ON s.id = f.submission_ref
       WHERE s.submission_id = ?1 AND f.key = 'duration_minutes'"
    ).unwrap();
    let rows = q.query_map(params![aid], |r| r.get::<_, String>(0)).unwrap();
    
    for r in rows {
        if let Ok(s) = r { 
            if let Ok(n) = s.parse::<i64>() { 
                out.push(n); 
            } 
        }
    }
    out
}

pub fn list_findings_for_submission(
    pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    sub_id: &str,
) -> Result<Vec<FindingRow>, String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, submission_ref, kind, key, value, created_at
        FROM findings
        WHERE submission_ref = ?1
        ORDER BY created_at ASC, kind ASC, key ASC
        "#
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map([sub_id], |r| {
        Ok(FindingRow {
            // correct columns:
            submission_ref: r.get::<_, String>(1)?, // submission_ref
            kind:           r.get::<_, String>(2)?, // kind
            key:            r.get::<_, String>(3)?, // key
            value:          r.get::<_, String>(4)?, // value
        })
    }).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}