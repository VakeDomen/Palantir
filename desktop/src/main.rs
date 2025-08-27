use iced::keyboard::key;
use iced::widget::text_input::Id;
use iced::widget::{self, button, column, container, row, scrollable, text, text_input, ProgressBar};
use iced::{keyboard, Application, Color, Command, Element, Length, Settings, Size, Subscription, Theme};
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::ZipWriter;
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
use iced::event::{self, Event};



#[derive(Default)]
struct PalantirApp {
    step: Step,
    assignment_id: String, // thing in url that student enters
    assignment_instance_id: String, // actual instance id needed for moodle api
    assignment_title: Option<String>,
    files: Vec<PathBuf>,
    // login
    username: String,
    password: String,
    moodle_token: Option<String>,
    // endpoints
    moodle_base: String,
    moodle_service: String,
    server_base: String,
    // ui
    status: String,
    progress_main: f32,
    progress_logs: f32,
    receipt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Login,
    EnterId,
    PickFiles,
    Submit,
    Progress,
    Done,
}

impl Default for Step {
    fn default() -> Self { Step::Login }
}
#[derive(Debug, Clone)]
enum Msg {
    // login
    UsernameChanged(String),
    PasswordChanged(String),
    LoginPressed,
    LoginFinished(Result<String, String>), // token on success

    // id check
    AssignmentIdChanged(String),
    CheckId,
    IdVerified(Result<AssignmentIdentifiers, String>), // (assignment_instance_id, name)

    // files and submission
    PickFiles,
    FilesChosen(Vec<PathBuf>),
    SubmitPressed,
    FinishedMain(Result<String, String>),
    FinishedLogs(Result<String, String>),
    TickMain(f32),
    TickLogs(f32),

    // tabs
    Event(Event),
}


#[derive(Serialize, Deserialize)]
struct Manifest {
    assignment_id: String,
    username: String,
    created_at: String,
    file_hashes: Vec<(String, String)>,
    client_version: String,
}

#[derive(Debug, Clone)]
pub struct AssignmentIdentifiers {
    pub cmid: String,
    pub instance: String,
    pub name: String,
}

#[tokio::main]
async fn main() -> iced::Result {
    let _ = dotenv::dotenv();
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
            moodle_service: std::env::var("MOODLE_SERVICE").unwrap_or_else(|_| "moodle_mobile_app".to_string()),
            server_base: std::env::var("SERVER_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
            step: Step::Login,
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

    fn subscription(&self) -> Subscription<Msg> {
        event::listen().map(Msg::Event)
    }

    fn update(&mut self, message: Msg) -> Command<Msg> {
        match message {
            Msg::AssignmentIdChanged(s) => {
                self.assignment_id = s;
                Command::none()
            }
            Msg::CheckId => {
                let Some(tok) = self.moodle_token.clone() else {
                    self.status = "please login first".into();
                    return Command::none();
                };
                let base = self.moodle_base.clone();
                let cmid = self.assignment_id.trim().to_string(); // user enters CMID here
                if cmid.is_empty() || !cmid.chars().all(|c| c.is_ascii_digit()) {
                    self.status = "invalid assignment id (cmid)".into();
                    return Command::none();
                }
                self.status = "validating assignment...".into();
                return Command::perform(async move { 
                    moodle_get_assignment_identifiers(&base, &tok, &cmid).await 
                }, Msg::IdVerified);
            }
            Msg::IdVerified(res) => {
                match res {
                    Ok(identifiers) => {
                        // replace the user-entered CMID with the real assignment instance id
                        self.assignment_id = identifiers.cmid;
                        self.assignment_instance_id = identifiers.instance;
                        self.assignment_title = Some(identifiers.name);
                        self.status.clear();
                        self.step = Step::PickFiles;
                    }
                    Err(e) => {
                        self.status = format!("could not validate: {}", e);
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
                let Some(tok) = self.moodle_token.clone() else {
                    self.status = "please login first".into();
                    return Command::none();
                };

                if self.files.is_empty() {
                    self.status = "no files selected".into();
                    return Command::none();
                }

                // move to progress screen
                self.step = Step::Progress;
                self.progress_main = 0.0;
                self.progress_logs = 0.0;

                // capture values for async tasks
                let base = self.moodle_base.clone();
                let sid  = self.assignment_id.clone(); 
                let aid  = self.assignment_instance_id.clone(); 
                let files = self.files.clone();
                let token = tok.clone();

                let server_base = self.server_base.clone();
                let manifest = build_manifest(&sid, &self.username, &self.files);

                // task 1: upload to Moodle and submit
                let main_task = async move {
                    let res = moodle_upload_and_submit(&base, &token, &aid, &files).await?;
                    Ok::<String, String>(res)
                };

                // task 2: zip logs and send to server
                let logs_task = async move {
                    let zip_path = zip_snapshot("/var/tmp/", &manifest)?;
                    let receipt = upload_logs(&server_base, &manifest, &zip_path).await?;
                    Ok::<String, String>(receipt)
                };

                Command::batch(vec![
                    Command::perform(main_task, Msg::FinishedMain),
                    Command::perform(logs_task, Msg::FinishedLogs),
                ])
            }
            Msg::UsernameChanged(s) => {
                self.username = s;
                Command::none()
            }
            Msg::PasswordChanged(s) => {
                self.password = s;
                Command::none()
            }
            Msg::FinishedMain(res) => {
                match res {
                    Ok(r) => {
                        self.status = format!("✅ {}", r);
                        self.progress_main = 1.0;
                    }
                    Err(e) => {
                        self.status = format!("❌ {}", e);
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
            Msg::UsernameChanged(s) => { 
                self.username = s; Command::none() 
            }
            Msg::PasswordChanged(s) => { 
                self.password = s; Command::none() 
            }
            Msg::LoginPressed => {
                self.status = "signing in...".into();
                let base = self.moodle_base.clone();
                let service = self.moodle_service.clone();
                let u = self.username.clone();
                let p = self.password.clone();
                Command::perform(async move { moodle_get_token(&base, &service, &u, &p).await }, Msg::LoginFinished)
            }
            Msg::LoginFinished(res) => {
                match res {
                    Ok(tok) => {
                        self.moodle_token = Some(tok);
                        self.status.clear();
                        self.step = Step::EnterId;
                    }
                    Err(e) => {
                        self.status = format!("login error: {}", e);
                        self.step = Step::Login;
                    }
                }
                Command::none()
            }
            Msg::AssignmentIdChanged(s) => { 
                self.assignment_id = s; Command::none() 
            }

            Msg::Event(event) => match event {
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: keyboard::Key::Named(key::Named::Tab),
                    modifiers,
                    ..
                }) => {
                    if modifiers.shift() {
                        widget::focus_previous()
                    } else {
                        widget::focus_next()
                    }
                }
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: keyboard::Key::Named(key::Named::Enter),
                    ..
                }) => {
                    if self.step == Step::Login {
                        self.status = "signing in...".into();
                        let base = self.moodle_base.clone();
                        let service = self.moodle_service.clone();
                        let u = self.username.clone();
                        let p = self.password.clone();
                        return Command::perform(async move { moodle_get_token(&base, &service, &u, &p).await }, Msg::LoginFinished);
                    };



                    Command::none()
                }
                _ => Command::none(),
            },
        }
    }

    fn view(&self) -> Element<Msg> {
        let title = |s: &str| text(s)
            .size(20)
            .style(theme::Text::Color(Color::from_rgb8(71, 85, 105)));

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
                    if let Some(name) = &self.assignment_title {
                        text(format!("Assignment: {}", name))
                            .style(theme::Text::Color(Color::from_rgb8(71, 85, 105)))
                    } else { text("") },
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
                let display_title = format!("Submit to: {}", self.assignment_title.clone().unwrap_or("Unknown".into()));
                let body = column![
                    title(&display_title),
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
            Step::Login => {
                let form = column![
                    text("Sign in to Moodle").size(22),
                    text_input("username", &self.username)
                        .on_input(Msg::UsernameChanged)
                        .id(Id::unique())
                        .padding(10)
                        .size(16)
                        .width(Length::Fill),
                    text_input("password", &self.password)
                        .on_input(Msg::PasswordChanged)
                        .id(Id::unique())
                        .secure(true)
                        .padding(10)
                        .size(16)
                        .width(Length::Fill),
                    row![
                        button("Login")
                            .on_press_maybe((!self.username.is_empty() && !self.password.is_empty()).then_some(Msg::LoginPressed))
                            .style(theme::Button::Custom(Box::new(PrimaryBtn)))
                            .padding(8)
                    ]
                    .spacing(12),
                    if !self.status.is_empty() { text(&self.status) } else { text("") },
                ]
                .spacing(16)
                .width(Length::Fixed(480.0));

                container(form)
                    .padding(24)
                    .style(theme::Container::Custom(Box::new(Card)))
                    .center_x()
                    .center_y()
                    .into()
            }
        };

    
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

    let file = File::create(&out_path)
        .map_err(|e| format!("create zip {}: {}", out_path.display(), e))?;
    
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::default();

    // manifest.json
    let manifest_json = serde_json::to_vec_pretty(manifest)
        .map_err(|e| format!("serialize manifest: {}", e))?;
    
    zip.start_file("manifest.json", opts)
        .map_err(|e| format!("start manifest.json: {}", e))?;
    
    zip.write_all(&manifest_json)
        .map_err(|e| format!("write manifest.json: {}", e))?;

    // add /var/tmp/palantir.log exactly
    let log_path = Path::new(snapshot_dir).join("palantir.log");
    
    if log_path.exists() {
    
        zip.start_file("snapshot/palantir.log", opts)
            .map_err(|e| format!("start file {}: {}", log_path.display(), e))?;
    
        let mut f = File::open(&log_path)
            .map_err(|e| format!("open {}: {}", log_path.display(), e))?;
    
        let mut buf = Vec::new();
    
        f.read_to_end(&mut buf)
            .map_err(|e| format!("read {}: {}", log_path.display(), e))?;
    
        zip.write_all(&buf)
            .map_err(|e| format!("write palantir.log into zip: {}", e))?;
    } else {
        return Err(format!("missing {}", log_path.display()));
    }

    zip.finish()
        .map_err(|e| format!("finish zip {}: {}", out_path.display(), e))?;
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

async fn moodle_get_token(base: &str, service: &str, username: &str, password: &str) -> Result<String, String> {
    let url = format!(
        "{}/login/token.php?service={}&username={}&password={}",
        base,
        urlencoding::encode(service),
        urlencoding::encode(username),
        urlencoding::encode(password)
    );
    let resp = reqwest::get(url).await.map_err(|e| e.to_string())?;
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| format!("unexpected token response: {}", text))?;

    if let Some(tok) = v.get("token").and_then(|t| t.as_str()) {
        return Ok(tok.to_string());
    }

    let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("login incorrect");
    Err(msg.to_string())
}

async fn moodle_upload_and_submit(base: &str, token: &str, assignment_id: &str, files: &[PathBuf]) -> Result<String, String> {
    let client = reqwest::Client::new();
    let mut itemid: Option<i64> = None;

    for (idx, path) in files.iter().enumerate() {
        let mut url = reqwest::Url::parse(&format!("{}/webservice/upload.php", base))
            .map_err(|e| e.to_string())?;
        
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("token", token);
            if let Some(id) = itemid { 
                qp.append_pair("itemid", &id.to_string()); 
            }
        }

        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| format!("read {:?}: {}", path, e))?;
        
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
            );
        let form = reqwest::multipart::Form::new().part("file_1", part);

        let resp = client
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("upload {:?}: {}", path, e))?;

        let body = resp
            .text()
            .await
            .map_err(|e| e.to_string())?;
        
        let arr: serde_json::Value = serde_json::from_str(&body)
            .map_err(|_| format!("unexpected upload response: {}", body))?;
        
        let first = arr
            .get(0)
            .ok_or_else(|| format!("empty upload response: {}", body))?;
        
        let id = first
            .get("itemid")
            .and_then(|n| n.as_i64())
            .ok_or_else(|| format!("missing itemid in: {}", first))?;

        if itemid.is_none() && idx == 0 { 
            itemid = Some(id); 
        }
    }


    let draft_id = itemid
        .ok_or_else(|| "no itemid returned".to_string())?;

    let url = format!("{}/webservice/rest/server.php", base);
    let body = format!(
        "wstoken={}&wsfunction=mod_assign_save_submission&moodlewsrestformat=json&assignmentid={}&plugindata[files_filemanager]={}",
        urlencoding::encode(token),
        assignment_id,
        draft_id, // numeric, does not need encoding
    );

    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;


    let text = resp.text().await.map_err(|e| e.to_string())?;

    check_save_submission_response(&text)?;
    moodle_submit_for_grading(&client, base, token, assignment_id).await?;


    Ok(format!("submitted assignment {} with draft {}", assignment_id, draft_id))
}

async fn moodle_get_assignment_identifiers(base: &str, token: &str, cmid: &str) -> Result<AssignmentIdentifiers, String> {
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

    let cmid = cmid.into();
    Ok(AssignmentIdentifiers{cmid, instance, name})
}

async fn moodle_submit_for_grading(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    assignment_id: &str,
) -> Result<(), String> {
    let url = format!("{}/webservice/rest/server.php", base);

    // attempt 1: with submission statement
    let body_with = format!(
        "wstoken={}&wsfunction=mod_assign_submit_for_grading&moodlewsrestformat=json&assignmentid={}&acceptsubmissionstatement=1",
        urlencoding::encode(token),
        assignment_id
    );

    let resp1 = client.post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body_with)
        .send().await.map_err(|e| e.to_string())?;

    let text1 = resp1.text().await.map_err(|e| e.to_string())?;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text1) {
        if v.get("exception").is_none() {
            return Ok(()); // success
        }
        // if this exact failure is an invalid_parameter, fall back without the flag
        if v.get("errorcode").and_then(|x| x.as_str()) == Some("invalidparameter") {
            // attempt 2: without the flag
            let body_no = format!(
                "wstoken={}&wsfunction=mod_assign_submit_for_grading&moodlewsrestformat=json&assignmentid={}",
                urlencoding::encode(token),
                assignment_id
            );
            let resp2 = client.post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body_no)
                .send().await.map_err(|e| e.to_string())?;
            let text2 = resp2.text().await.map_err(|e| e.to_string())?;
            if serde_json::from_str::<serde_json::Value>(&text2)
                .ok()
                .and_then(|v2| v2.get("exception").cloned())
                .is_none()
            {
                return Ok(());
            }
            return Err(format!("submit_for_grading failed: {}", text2));
        }
        return Err(format!("submit_for_grading failed: {}", text1));
    } else {
        // non-JSON usually means success (older Moodle returns empty body), but be strict:
        return Ok(());
    }
}

fn check_save_submission_response(text: &str) -> Result<(), String> {
    // success on many Moodle versions is exactly an empty array: []
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
        match val {
            serde_json::Value::Array(arr) => {
                if arr.is_empty() {
                    return Ok(());
                }
                // warnings present
                // build a compact, user friendly error using warningcode and message
                let mut lines = Vec::new();
                for w in arr {
                    let code = w.get("warningcode").and_then(|x| x.as_str()).unwrap_or("warning");
                    let msg  = w.get("item").and_then(|x| x.as_str())
                         .or_else(|| w.get("message").and_then(|x| x.as_str()))
                         .unwrap_or("unknown");
                    lines.push(format!("{}: {}", code, msg));
                }
                return Err(format!("save_submission warnings: {}", lines.join("; ")));
            }
            serde_json::Value::Object(obj) => {
                if obj.get("exception").is_some() {
                    return Err(format!("save_submission failed: {}", text));
                }
                // some sites may return {} or another benign object
                return Ok(());
            }
            _ => return Ok(()),
        }
    } else {
        // non-JSON or unexpected, treat as success to mirror Moodle’s older behaviors
        Ok(())
    }
}
