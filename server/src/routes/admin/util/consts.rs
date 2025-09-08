/// Process name buckets
pub const BROWSERS: &[&str] = &[
    "firefox", 
    "chrome", 
    "chromium", 
    "brave", 
    "edge", 
    "opera"
];
pub const SHELLS: &[&str] = &[
    "bash", 
    "zsh", 
    "fish", 
    "sh", 
    "dash"
];



pub const REMOTE_TOOLS: &[&str] = &[
    "anydesk", 
    "teamviewer", 
    "rustdesk", 
    "remmina", 
    "x11vnc",
    "vino", 
    "vnc",
    "zoom", 
    "teams", 
    "discord", 
    "slack",
    "skype",
    "gotomeeting",
    "webex",
    "jitsi",
    "google-meet",
    "msteams",
    "telegram",
    "signal",
];

pub const SSH_LIKE: &[&str] = &[
    "ssh", 
    "scp", 
    "sftp", 
    "mosh"
];

pub const DOWNLOAD_TOOLS: &[&str] = &[
    "curl",
    "wget",
    "pip",
    "pip3",
    "conda",
    "npm",
    "pnpm",
    "yarn",
    "apt",
    "dnf",
    "pacman",
];

/// Domain categories used in analysis
pub const SEARCH_BASES: &[&str] = &[
    "google.com", 
    "bing.com", 
    "duckduckgo.com"
];

pub const QNA_BASES: &[&str] = &[
    "stackoverflow.com", 
    "stackexchange.com"
];
pub const CODE_HOST_BASES: &[&str] = &[
    "github.com", 
    "gitlab.com", 
    "bitbucket.org"
];

pub const PKG_BASES: &[&str] = &[
    "pypi.org",
    "pythonhosted.org",
    "npmjs.com",
    "registry.npmjs.org",
    "crates.io",
];

pub const CLOUD_BASES: &[&str] = &[
    "drive.google.com",
    "dropbox.com",
    "mega.nz",
    "wetransfer.com",
    "pastebin.com",
    "hastebin.com",
    "ghostbin.com",
];

/// AI provider domains. Prefer matching by base domain.
/// Keep tight to reduce false positives.
pub const AI_PROVIDER_BASES: &[&str] = &[
    // OpenAI
    "openai.com",
    "chatgpt.com",

    // Anthropic
    "anthropic.com",
    "claude.ai",

    // Google
    "ai.google",
    "deepmind.com",
    "gemini.google.com",

    // Microsoft
    "cognitive.microsoft.com",
    "githubcopilot.com",
    "openai.azure.com",
    "azureopenai.com",

    // Meta
    "ai.meta.com",
    "llama.meta.com",

    // Others
    "mistral.ai",
    "cohere.ai",
    "stability.ai",
    "ai21.com",
    "perplexity.ai",
    "huggingface.co",
    "replicate.com",
    "runpod.io",
    "openrouter.ai",
    "poe.com",
    "x.ai",
    "you.com",
    "character.ai",
    "elevenlabs.io",
    "jasper.ai",
    "writesonic.com",
    "copy.ai",
    "rytr.me",
    "forefront.ai",
    "midjourney.com",
    "replit.com",
];


/// Private IPv4 prefixes checked by simple starts_with
pub const PRIVATE_IPV4_PREFIXES: &[&str] = &[
    "10.", 
    "192.168.",
    "172.16.", 
    "172.17.", 
    "172.18.", 
    "172.19.", 
    "172.20.", 
    "172.21.", 
    "172.22.",
    "172.23.", 
    "172.24.", 
    "172.25.", 
    "172.26.", 
    "172.27.", 
    "172.28.", 
    "172.29.",
    "172.30.", 
    "172.31.",
];

/// Severity strings
pub const KIND_META: &str    = "meta";
pub const KIND_PROC: &str    = "proc";
pub const KIND_NET: &str     = "net";
pub const KIND_ANOMALY: &str = "anomaly";

// ---- Finding keys ----
// --- metadata about submission / session ---
pub const FK_ZIP_NAME: &str         = "zip_name";          // original uploaded archive filename
pub const FK_FIRST_TS: &str         = "first_ts";          // timestamp of first recorded event
pub const FK_LAST_TS: &str          = "last_ts";           // timestamp of last recorded event
pub const FK_DURATION_MINUTES: &str = "duration_minutes";  // total observed session duration in minutes
pub const FK_MAX_IDLE_SECONDS: &str = "max_idle_seconds";  // longest inactivity gap (seconds)
pub const FK_SEAT_IP: &str          = "seat_ip";           // most common private LAN IP used
pub const FK_DEVICE_KEY: &str       = "device_key";        // device identity key (currently equals seat_ip)

// --- process activity metrics ---
pub const FK_TOTAL_PROC_STARTS: &str        = "total_proc_starts";        // total number of process start events
pub const FK_TOTAL_PROC_STOPS: &str         = "total_proc_stops";         // total number of process stop events
pub const FK_TOP_PROC: &str                 = "top_proc";                 // most frequently started processes (name:count)
pub const FK_BROWSER_RUNTIME_SECONDS: &str  = "browser_runtime_seconds";  // cumulative runtime of browser processes
pub const FK_HAD_BROWSER: &str              = "had_browser";              // whether a browser was ever launched
pub const FK_SHELL_INVOCATIONS: &str        = "shell_invocations";        // number of shell/terminal launches
pub const FK_EXTERNAL_DOWNLOAD_TOOL_COUNT: &str = "external_download_tool_count"; // usage count of tools like curl/wget/npm/etc

// --- network activity metrics ---
pub const FK_TOTAL_NET_EVENTS: &str         = "total_net_events";         // total number of network events
pub const FK_REQUESTS_PER_MIN: &str         = "requests_per_min";         // average DNS/connection requests per minute
pub const FK_UNIQUE_DOMAINS: &str           = "unique_domains";           // number of distinct domains contacted
pub const FK_TOP_DOMAIN: &str               = "top_domain";               // most contacted domains (base:count)
pub const FK_TOP_SRC_IP: &str               = "top_src_ip";               // most active local source IPs
pub const FK_AI_DOMAIN: &str                = "ai_domain";                // contacted AI service domains (base:count)
pub const FK_BURST_MAX_EVENTS_PER_MIN: &str = "burst_max_events_per_min"; // peak number of events in a single minute
pub const FK_FINAL5_NET_EVENTS: &str        = "final5_net_events";        // number of network events in final 5 minutes

// --- anomaly flags ---
pub const FK_REMOTE_COLLAB_TOOL_SEEN: &str = "remote_collab_tool_seen"; // detected remote desktop / collab software
pub const FK_SSH_ACTIVITY: &str            = "ssh_activity";            // detected SSH/SCP/SFTP/Mosh usage
pub const FK_AI_HITS_TOTAL: &str           = "ai_hits_total";           // total number of AI-related network events
pub const FK_AI_RATIO_PERCENT: &str        = "ai_ratio_percent";        // % of AI events relative to all DNS queries
pub const FK_LOOPBACK_DOMINATED: &str      = "loopback_dominated";      // >80% of traffic stayed on localhost (127.0.0.1)

// --- categorized domain hits ---
pub const FK_QNA_HITS: &str        = "qna_hits";        // visits to Q&A sites (StackOverflow, StackExchange, etc.)
pub const FK_CODE_HOST_HITS: &str  = "code_host_hits";  // visits to code hosting (GitHub, GitLab, Bitbucket)
pub const FK_SEARCH_HITS: &str     = "search_hits";     // visits to search engines (Google, Bing, DuckDuckGo)
pub const FK_PKG_HITS: &str        = "pkg_hits";        // requests to package registries (PyPI, npm, crates.io, etc.)
pub const FK_CLOUD_HITS: &str      = "cloud_hits";      // uploads/downloads to cloud storage/file sharing services


// Which keys can be filtered as numbers (CAST(value AS INTEGER))
pub const ALLOWED_KEYS_NUM: &[&str] = &[
    // session & intensity
    FK_DURATION_MINUTES,
    FK_REQUESTS_PER_MIN,
    FK_TOTAL_NET_EVENTS,
    FK_UNIQUE_DOMAINS,
    FK_BURST_MAX_EVENTS_PER_MIN,
    FK_FINAL5_NET_EVENTS,

    // proc counts
    FK_TOTAL_PROC_STARTS,
    FK_TOTAL_PROC_STOPS,
    FK_BROWSER_RUNTIME_SECONDS,
    FK_SHELL_INVOCATIONS,
    FK_EXTERNAL_DOWNLOAD_TOOL_COUNT,

    // AI / categories
    FK_AI_HITS_TOTAL,
    FK_AI_RATIO_PERCENT,   // percent stored as number
    FK_QNA_HITS,
    FK_CODE_HOST_HITS,
    FK_SEARCH_HITS,
    FK_PKG_HITS,
    FK_CLOUD_HITS,
];

// Which keys can be filtered as booleans (value ~ true/false/1/0/yes/no)
pub const ALLOWED_KEYS_BOOL: &[&str] = &[
    FK_HAD_BROWSER,
    FK_REMOTE_COLLAB_TOOL_SEEN,
    FK_SSH_ACTIVITY,
    // (loopback_dominated is "X/Y" string -> not boolean)
];

// Supported operators
pub const ALLOWED_OPS: &[&str] = &["gt","ge","eq","le","lt","ne","exists"];


/// System-ish noise we hide by default in the process timeline.
pub const SYSTEM_HIDE_PROCS: &[&str] = &[
    "(sd-pam)",
    "systemd",
    "sd_dummy",
    "dbus",
    "polkit",
    "gvfs",
    "xdg",
    "xdg-desktop-portal",
    "mutter",
    "gnome-shell",
    "gjs",
    "xwayland",
    "nautilus",
    "dconf-service",
    "goa-daemon",
    "goa-identity-service",
    "gcr-ssh-agent",
    "pipewire",
    "wireplumber",
    "sd_espeak-ng",
    "sd_espeak-ng-mb",
    "speech-dispatcher",
    "localsearch",
    "localsearch-3",
    "tracker",
    "tracker-miner",
    "chrome_crashpad",
    "crashhelper",
    "privileged",
    "webextensions",
    "mpris-proxy",
    "snap",
    "snapd",
    "flatpak",
    "gdm-wayland-session",
    "gdm-session-worker",
    "sleep",
    "firmware-notification",
    "pingsender",
    "desktop-launcher",
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "ls",
    "prefetch",
    "cpuusage",
    "cc",
    "evolution-calendar",
    "evolution-address",
    "evolution-source-reg",
    "evolution-alarm-notify",
    "evolution",
    "localsearch-3",
    "localsearch-ext",
    "localsearch",
    "evolution-",
    "desktop-launch",
    "apport",
    "gitstatusd-linu",
    "palantir_server",
    "palantir_deskto",
    "build-script-builder",
    "rdd",
    "cpuusage.sh",
    "rdd",
    "socket",
    "forkserver",
    "xwayland",
    "mutter",
    "mutter-x11-fram",
    "gjs",
    "gdm-wayland-ses",
    "gdm-session-worker",
    "dconf-service",
    "goa-daemon",
    "pressure-vessel",
    "srt-bwrap",
    "srt-logger",
    "goa-identity-se",
    "mpris-proxy",
    "ld",
    "collect2",
    "vsce-sign",
    "d3ddriverquery6",
    "gdbus",
    "prefetch:"

];

/// Procs that carry cheating risk; highlight them in UI and raise attention in analysis.
pub const CHEAT_HIGHLIGHT_PROCS: &[&str] = &[
    "tunnel",
    "docker-buildx",
    "git",
    "git-remote-https",
    "telegram",
    "ollama",
    "insomnia",
    "curl",
    "ssh",
    "ssh-agent",
    "cargo",
    "rustc",
    "docker",
    "firefox",
    "chrome",
    "chromium",
    "brave",
    "edge",
    "opera",
    "web",
    "chatgpt",
    "claude",
    "ollama",
    "telegram-desktop",
    "discord",
    "slack",
    "pwsh",
    "powershell",
    "ssh",
    "ssh-agent",
    "scp",
    "sftp",
    "rsync",
    "teamviewer",
    "anydesk",
    "rustdesk",
    "remmina",
    "xrdp",
    "vnc",
    "curl",
    "wget",
    "httpie",
    "insomnia",
    "postman",
    "pip",
    "pip3",
    "poetry",
    "conda",
    "npm",
    "pnpm",
    "yarn",
    "cargo",
    "go",
    "make",
    "cmake",
    "gcc",
    "g++",
    "clang",
    "docker",
    "podman",
    "kubectl",
    "minikube",
    "qemu",
    "virt-manager",
    "virtualbox",
    "vmware",
    "vagrant",
    "(sd-pam)",
    "chrome_crashpad",
    "crashhelper",
    "webextensions",
    "privileged",
    "pingsender",
    "nautilus",
    "snap",
    "snapd",
    "cloud-drive-",
    "steam-runtime-l",
    "steamwebhelper",
];

/// Minimum percentile a submission must exceed to be considered an outlier in net events.
/// Example: 95.0 means "flag anything >= 95th percentile".
pub const OUTLIER_MIN_FLAG_PERCENTILE: i32 = 75;

/// Small helper: guess base domain by stripping left-most label
pub fn base_domain_guess(host: &str) -> String {
    let mut parts: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        let last = parts.pop().unwrap();
        let prev = parts.pop().unwrap();
        format!("{prev}.{last}")
    } else {
        host.to_ascii_lowercase()
    }
}

/// Helpers for proc name matching
pub fn name_is_in(name: &str, set: &[&str]) -> bool {
    let c = name.to_ascii_lowercase();
    set.iter().any(|b| c == *b || c.contains(b) || c.ends_with(&format!("/{b}")) || c.starts_with(&format!("{b} ")))
}

/// Simple private IPv4 check
pub fn is_private_ipv4(ip: &str) -> bool {
    PRIVATE_IPV4_PREFIXES.iter().any(|p| ip.starts_with(p))
}
