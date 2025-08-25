use iced::widget::{button, column, container, row, scrollable, text, text_input, ProgressBar};
use iced::{Application, Color, Command, Element, Length, Settings, Size, Theme};
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use walkdir::WalkDir;
use zip::write::FileOptions;
use iced::theme;
use iced::Border;
use iced::border::Radius;
use iced::Background;
use iced::Renderer;


#[derive(Default)]
struct PalantirApp {
    step: Step,
    assignment_id: String,
    assignment_title: Option<String>,
    files: Vec<PathBuf>,
    show_credentials: bool,
    username: String,
    password: String,
    moodle_base: String,
    server_base: String,
    status: String,
    progress_main: f32,
    progress_logs: f32,
    receipt: Option<String>,
}

#[derive(Debug, Clone)]
enum Step {
    EnterId,
    PickFiles,
    Submit,
    Progress,
    Done,
}

impl Default for Step {
    fn default() -> Self {
        Step::EnterId
    }
}

#[derive(Debug, Clone)]
enum Msg {
    AssignmentIdChanged(String),
    CheckId,
    IdVerified(Result<Option<String>, String>), // title if available
    PickFiles,
    FilesChosen(Vec<PathBuf>),
    SubmitPressed,
    UsernameChanged(String),
    PasswordChanged(String),
    ConfirmCredentials,
    StartSubmission,
    FinishedMain(Result<String, String>),
    FinishedLogs(Result<String, String>),
    TickMain(f32),
    TickLogs(f32),
    CancelCredentials,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    assignment_id: String,
    username: String,
    created_at: String,
    file_hashes: Vec<(String, String)>,
    client_version: String,
}

#[tokio::main]
async fn main() -> iced::Result {
    let mut settings = Settings::default();
    settings.window.size = Size::new(900.0, 640.0);
    PalantirApp::run(settings)
}



impl Application for PalantirApp {
    type Executor = iced::executor::Default;
    type Message = Msg;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Msg>) {
        (
            PalantirApp {
                moodle_base: std::env::var("MOODLE_BASE_URL").unwrap_or_else(|_| "http://localhost".to_string()),
                server_base: std::env::var("SERVER_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
                ..Default::default()
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        "Palantir".into()
    }

    fn theme(&self) -> Theme {
        let palette = iced::theme::Palette {
            background: Color::from_rgb8(248, 250, 252),
            text:       Color::from_rgb8(15, 23, 42),
            primary:    Color::from_rgb8(59, 130, 246),
            success:    Color::from_rgb8(34, 197, 94),
            danger:     Color::from_rgb8(239, 68, 68),
        };
        Theme::custom("Palantir".to_string(), palette)
    }

    fn update(&mut self, message: Msg) -> Command<Msg> {
        match message {
            Msg::AssignmentIdChanged(s) => {
                self.assignment_id = s;
                Command::none()
            }
            Msg::CheckId => {
                self.status = "checking assignment id".into();
                // For now, do a format check and move on.
                // In a later iteration, call Moodle for a real check without credentials if possible.
                let id_ok = self.assignment_id.trim().chars().all(|c| c.is_ascii_digit());
                if id_ok {
                    Command::perform(async { Ok::<_, String>(None) }, |res| Msg::IdVerified(res))
                } else {
                    Command::perform(async { Err::<Option<String>, _>("invalid id".into()) }, Msg::IdVerified)
                }
            }
            Msg::IdVerified(res) => {
                match res {
                    Ok(title) => {
                        self.assignment_title = title;
                        self.step = Step::PickFiles;
                        self.status = "".into();
                    }
                    Err(e) => {
                        self.status = format!("id check failed: {}", e);
                    }
                }
                Command::none()
            }
            Msg::PickFiles => {
                if let Some(paths) = FileDialog::new().set_directory(".").pick_files() {
                    return Command::perform(async move { paths }, Msg::FilesChosen);
                }
                Command::none()
            }
            Msg::FilesChosen(list) => {
                self.files = list;
                Command::none()
            }
            Msg::SubmitPressed => {
                self.show_credentials = true;
                Command::none()
            }
            Msg::UsernameChanged(s) => {
                self.username = s;
                Command::none()
            }
            Msg::PasswordChanged(s) => {
                self.password = s;
                Command::none()
            }
            Msg::ConfirmCredentials => {
                self.show_credentials = false;
                self.step = Step::Progress;
                self.progress_main = 0.0;
                self.progress_logs = 0.0;
                let manifest = build_manifest(&self.assignment_id, &self.username, &self.files);
                let moodle_base = self.moodle_base.clone();
                let server_base = self.server_base.clone();
                let username = self.username.clone();
                let password = self.password.clone();
                let assignment_id = self.assignment_id.clone();
                let files = self.files.clone();

                let main_task = async move {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let _ = (moodle_base, username, password, assignment_id, files);
                    Ok::<String, String>("moodle-receipt".into())
                };

                let logs_task = async move {
                    // zip snapshot and send to server
                    let zip_path = zip_snapshot("/var/tmp/palantir/snapshot", &manifest)?;
                    let receipt = upload_logs(&server_base, &manifest, &zip_path).await?;
                    Ok::<String, String>(receipt)
                };

                return Command::batch(vec![
                    Command::perform(main_task, Msg::FinishedMain),
                    Command::perform(logs_task, Msg::FinishedLogs),
                ]);
            }
            Msg::StartSubmission => Command::none(),
            Msg::FinishedMain(res) => {
                match res {
                    Ok(r) => {
                        self.status = format!("moodle ok receipt {}", r);
                        self.progress_main = 1.0;
                    }
                    Err(e) => {
                        self.status = format!("moodle error {}", e);
                        self.progress_main = 1.0;
                    }
                }
                if self.progress_logs >= 1.0 {
                    self.step = Step::Done;
                }
                Command::none()
            }
            Msg::FinishedLogs(res) => {
                match res {
                    Ok(r) => {
                        self.status = format!("logs uploaded receipt {}", r);
                        self.progress_logs = 1.0;
                        self.receipt = Some(r);
                    }
                    Err(e) => {
                        self.status = format!("log upload error {}", e);
                        self.progress_logs = 1.0;
                    }
                }
                if self.progress_main >= 1.0 {
                    self.step = Step::Done;
                }
                Command::none()
            }
            Msg::TickMain(p) => {
                self.progress_main = p;
                Command::none()
            }
            Msg::TickLogs(p) => {
                self.progress_logs = p;
                Command::none()
            }
            Msg::CancelCredentials => {
                self.show_credentials = false;
                Command::none()
            }

        }
    }

    fn view(&self) -> Element<Msg> {
        let subtitle = |s: &str| text(s)
            .size(16)
            .style(theme::Text::Color(Color::from_rgb8(71, 85, 105)));

        let content: Element<_> = match self.step {
            Step::EnterId => {
                let id_ok = !self.assignment_id.trim().is_empty()
                    && self.assignment_id.chars().all(|c| c.is_ascii_digit());

                let form = column![
                    subtitle("Enter the assignment id from Moodle (professor should provide you one)"),
                    text_input("assignment id", &self.assignment_id)
                        .on_input(Msg::AssignmentIdChanged)
                        .padding(10)
                        .size(16)
                        .width(Length::Fill),
                    row![
                        button("Check")
                            .on_press_maybe(id_ok.then_some(Msg::CheckId))
                            .style(theme::Button::Custom(Box::new(PrimaryBtn)))
                            .padding(8)
                    ]
                    .spacing(12),
                    if !self.status.is_empty() { text(&self.status) } else { text("") },
                ]
                .spacing(16)
                .width(Length::Fixed(640.0));

                container(form)
                    .padding(24)
                    .style(theme::Container::Custom(Box::new(Card)))
                    .center_x()
                    .center_y()
                    .into()

            }

            Step::PickFiles => {
                
                // actions row (unchanged, just showing context)
                let actions = row![
                    button("Add files")
                        .on_press(Msg::PickFiles)
                        .style(theme::Button::Custom(Box::new(PrimaryBtn)))
                        .padding(8),
                ]
                .spacing(12);

                // build content for the list without using `fold`
                // this avoids the generic type inference issue
                let list_content: Element<Msg> = if self.files.is_empty() {
                    column![
                        text("No files selected yet")
                            .style(theme::Text::Color(Color::from_rgb8(100, 116, 139)))
                    ]
                    .spacing(8)
                    .into()
                } else {
                    let items: Vec<Element<Msg>> = self
                        .files
                        .iter()
                        .map(|p| text(p.to_string_lossy()).size(15).into())
                        .collect();

                    // `column(items)` is concrete and easy to infer
                    column(items)
                        .spacing(8)
                        .into()
                };

                // then use `list_content` here
                let body = column![
                    subtitle("Pick all files and folders you want to submit"),
                    text(format!(
                        "  {} items  •  {}",
                        self.files.len(),
                        pretty_size(total_size(&self.files))
                    ))
                    .style(theme::Text::Color(Color::from_rgb8(71, 85, 105))),
                    actions,
                    scrollable(list_content)
                        .height(Length::Fixed(240.0))
                        .width(Length::Fill),
                    row![
                        button("Continue")
                            .on_press_maybe((!self.files.is_empty()).then_some(Msg::SubmitPressed))
                            .style(theme::Button::Custom(Box::new(PrimaryBtn)))
                            .padding(8),
                    ]
                    .spacing(12),
                    if !self.status.is_empty() { text(&self.status) } else { text("") },
                ]
                .spacing(16)
                .width(Length::Fixed(720.0));

                container(body)
                    .padding(24)
                    .style(theme::Container::Custom(Box::new(Card)))
                    .into()


            }

            Step::Submit => {
                let body = column![
                    subtitle("Review and submit"),
                    text("When you click Submit, you will be asked for your Moodle credentials.").size(15),
                    row![ 
                        button("Submit")
                            .on_press(Msg::SubmitPressed)
                            .style(theme::Button::Custom(Box::new(PrimaryBtn)))
                            .padding(8) 
                    ]
                    .spacing(12),
                    if !self.status.is_empty() { text(&self.status) } else { text("") },
                ]
                .spacing(16)
                .width(Length::Fixed(600.0));

                container(body)
                    .padding(24)
                    .style(theme::Container::Custom(Box::new(Card)))
                    .into()

            }

            Step::Progress => {
                let body = column![
                    subtitle("Uploading to Moodle and sending logs"),
                    text("Moodle").size(14),
                    ProgressBar::new(0.0..=1.0, self.progress_main),
                    text("Logs").size(14),
                    ProgressBar::new(0.0..=1.0, self.progress_logs),
                    if !self.status.is_empty() { text(&self.status)} else { text("").into() },
                ]
                .spacing(16)
                .width(Length::Fixed(600.0));

                container(body)
                    .padding(24)
                    .style(theme::Container::Custom(Box::new(Card)))
                    .into()
            }

            Step::Done => {
                let body = column![
                    subtitle("Submission complete"),
                    if let Some(r) = &self.receipt {
                        text(format!("Receipt {}", r)).size(16)
                    } else {
                        text("No receipt available").size(16)
                    },
                    text(&self.status),
                ]
                .spacing(16)
                .width(Length::Fixed(600.0));

                container(body)
                    .padding(24)
                    .style(theme::Container::Custom(Box::new(Card)))
                    .into()
            }
        };

        if self.show_credentials {
            let modal = container(
                column![
                    text("Moodle credentials").size(22),
                    text_input("username", &self.username)
                        .on_input(Msg::UsernameChanged)
                        .padding(10)
                        .size(16)
                        .width(Length::Fill),
                    text_input("password", &self.password)
                        .on_input(Msg::PasswordChanged)
                        .secure(true)
                        .padding(10)
                        .size(16)
                        .width(Length::Fill),
                    row![
                        button("Confirm")
                            .on_press(Msg::ConfirmCredentials)
                            .style(theme::Button::Custom(Box::new(PrimaryBtn)))
                            .padding(8),
                        button("Back")
                            .on_press(Msg::CancelCredentials)
                            .style(theme::Button::Custom(Box::new(PrimaryBtn)))
                            .padding(8)

                    ]
                    .spacing(16)
                    
                ]
                .spacing(12)
                .width(Length::Fixed(420.0)),
            )
            .padding(24)
            .style(theme::Container::Custom(Box::new(Card)));

            return container(modal)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .center_y()
                .style(theme::Container::Custom(Box::new(PageBg)))
                .into();
        }

        container(
            container(content)
                .width(Length::Shrink)
                .center_x()
                .center_y(),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x()
        .center_y()
        .style(theme::Container::Custom(Box::new(PageBg)))
        .into()


    }

}

// helpers

fn build_manifest(assignment_id: &str, username: &str, files: &[PathBuf]) -> Manifest {
    let mut file_hashes = Vec::new();
    for p in files {
        if p.is_file() {
            let h = hash_file(p);
            file_hashes.push((p.file_name().unwrap().to_string_lossy().to_string(), h));
        } else if p.is_dir() {
            for e in WalkDir::new(p) {
                let e = e.unwrap();
                if e.path().is_file() {
                    let h = hash_file(e.path());
                    let rel = e.path().strip_prefix(p).unwrap_or(e.path());
                    file_hashes.push((format!("{}/{}", p.file_name().unwrap().to_string_lossy(), rel.to_string_lossy()), h));
                }
            }
        }
    }
    let created_at = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap();
    Manifest {
        assignment_id: assignment_id.to_string(),
        username: username.to_string(),
        created_at,
        file_hashes,
        client_version: "palantir-desktop-0.1.0".to_string(),
    }
}

fn hash_file(path: &Path) -> String {
    let mut f = File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    hex::encode(hasher.finalize())
}

fn zip_snapshot(snapshot_dir: &str, manifest: &Manifest) -> Result<PathBuf, String> {
    let out_name = format!(
        "palantir-snapshot-{}-{}.zip",
        manifest.assignment_id,
        manifest.username
    );
    let out_path = std::env::temp_dir().join(out_name);
    let file = File::create(&out_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);

    let opts = FileOptions::default();

    // add manifest json
    let manifest_json = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
    zip.start_file("manifest.json", opts).map_err(|e| e.to_string())?;
    zip.write_all(&manifest_json).map_err(|e| e.to_string())?;

    // add snapshot directory if present
    let path = Path::new(snapshot_dir);
    if path.exists() {
        for entry in WalkDir::new(path) {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_file() {
                let rel = p.strip_prefix(path).unwrap();
                let rel_str = rel.to_string_lossy();
                zip.start_file(format!("snapshot/{}", rel_str), opts).map_err(|e| e.to_string())?;
                let mut f = File::open(p).map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
                zip.write_all(&buf).map_err(|e| e.to_string())?;
            }
        }
    }

    zip.finish().map_err(|e| e.to_string())?;
    Ok(out_path)
}

async fn upload_logs(server_base: &str, manifest: &Manifest, zip_path: &Path) -> Result<String, String> {
    let url = format!(
        "{}/api/v1/logs?submission_id={}&student_name={}&moodle_assignment_id={}&client_version={}",
        server_base,
        urlencoding::encode(&manifest.assignment_id),
        urlencoding::encode(&manifest.username),
        urlencoding::encode(&manifest.assignment_id),
        urlencoding::encode(&manifest.client_version),
    );

    let file_part = reqwest::multipart::Part::stream(tokio::fs::read(zip_path).await.map_err(|e| e.to_string())?)
        .file_name(
            zip_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        );

    let form = reqwest::multipart::Form::new().part("log_zip", file_part);

    let client = reqwest::Client::new();
    let res = client.post(url).multipart(form).send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("server error {}", res.status()));
    }
    let v: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    let receipt = v.get("receipt_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Ok(receipt)
}

struct Card;

impl container::StyleSheet for Card {
    type Style = Theme;
    fn appearance(&self, _style: &Theme) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(Color::from_rgb8(255, 255, 255))),
            text_color: None,
            border: Border {
                width: 1.0,
                color: Color::from_rgb8(226, 232, 240),
                radius: Radius::from(16.0),
            },
            shadow: Default::default(),
        }
    }
}

struct PageBg;

impl container::StyleSheet for PageBg {
    type Style = Theme;
    fn appearance(&self, style: &Theme) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(style.palette().background)),
            text_color: None,
            border: Border {
                width: 0.0,
                color: Color::TRANSPARENT,
                radius: Radius::from(0.0),
            },
            shadow: Default::default(),
        }
    }
}


struct PrimaryBtn;

impl button::StyleSheet for PrimaryBtn {
    type Style = Theme;

    fn active(&self, style: &Theme) -> button::Appearance {
        let p = style.palette().primary;
        button::Appearance {
            background: Some(Background::Color(p)),
            text_color: Color::WHITE,
            border: Border {
                width: 0.0,
                color: Color::TRANSPARENT,
                radius: Radius::from(10.0),
            },
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Theme) -> button::Appearance {
        let mut a = self.active(style);
        a.background = Some(Background::Color(tint(style.palette().primary, 1.08)));
        a
    }

    fn disabled(&self, _style: &Theme) -> button::Appearance {
        button::Appearance {
            background: Some(Background::Color(Color::from_rgb8(203, 213, 225))),
            text_color: Color::from_rgb8(248, 250, 252),
            border: Border {
                width: 0.0,
                color: Color::TRANSPARENT,
                radius: Radius::from(10.0),
            },
            ..Default::default()
        }
    }
}


fn tint(c: Color, factor: f32) -> Color {
    let clamp = |x: f32| x.min(1.0);
    Color::from_rgba(clamp(c.r * factor), clamp(c.g * factor), clamp(c.b * factor), c.a)
}


fn pretty_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB { format!("{:.2} GB", b / GB) }
    else if b >= MB { format!("{:.2} MB", b / MB) }
    else if b >= KB { format!("{:.0} KB", b / KB) }
    else { format!("{} B", bytes) }
}

fn total_size(paths: &[PathBuf]) -> u64 {
    let mut total = 0u64;
    for p in paths {
        if p.is_file() {
            if let Ok(md) = std::fs::metadata(p) { total += md.len(); }
        } else if p.is_dir() {
            for e in WalkDir::new(p) {
                if let Ok(e) = e {
                    if e.path().is_file() {
                        if let Ok(md) = e.metadata() { total += md.len(); }
                    }
                }
            }
        }
    }
    total
}
