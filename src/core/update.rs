use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::constants::APP_VERSION;

const RELEASE_API: &str = "https://api.github.com/repos/EduardRe/SessionPasswordExporter";
const DOWNLOAD_PREFIX: &str =
    "https://github.com/EduardRe/SessionPasswordExporter/releases/download/";
const USER_AGENT: &str = concat!("session-password-exporter/", env!("CARGO_PKG_VERSION"));
const MAX_DOWNLOAD_BYTES: u64 = 80 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn current() -> Self {
        Self::parse(APP_VERSION).unwrap_or(Self {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }

    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateKind {
    Installer,
    Portable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailableUpdate {
    pub version: Version,
    pub kind: UpdateKind,
    pub asset_name: String,
    pub download_url: String,
    pub checksum_name: String,
    pub checksum_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedUpdate {
    pub kind: UpdateKind,
    pub path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateError {
    Network,
    Response,
    Asset,
    Checksum,
    Save,
}

pub fn current_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "x86" => "x86",
        other => other,
    }
}

pub fn version_in_text(value: &str) -> Option<Version> {
    let mut rest = value;
    while let Some(start) = rest.find(|character: char| character.is_ascii_digit()) {
        rest = &rest[start..];
        let end = rest
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(rest.len());
        if let Some(version) = Version::parse(&rest[..end]) {
            return Some(version);
        }
        rest = &rest[end.max(1)..];
    }
    None
}

pub fn select_newer_update(
    releases_json: &str,
    current: Version,
    kind: UpdateKind,
    architecture: &str,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    let releases: Vec<GitHubRelease> =
        serde_json::from_str(releases_json).map_err(|_| UpdateError::Response)?;
    let mut selected = None;
    for release in releases {
        let Some(update) = update_from_release(&release, kind, architecture)? else {
            continue;
        };
        if update.version <= current {
            continue;
        }
        let replace = selected
            .as_ref()
            .is_none_or(|current_best: &AvailableUpdate| update.version > current_best.version);
        if replace {
            selected = Some(update);
        }
    }
    Ok(selected)
}

pub fn package_from_release(
    release_json: &str,
    kind: UpdateKind,
    architecture: &str,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    let release: GitHubRelease =
        serde_json::from_str(release_json).map_err(|_| UpdateError::Response)?;
    update_from_release(&release, kind, architecture)
}

fn update_from_release(
    release: &GitHubRelease,
    kind: UpdateKind,
    architecture: &str,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let Some(version) =
        version_in_text(&release.name).or_else(|| version_in_text(&release.tag_name))
    else {
        return Ok(None);
    };
    let asset_name = match kind {
        UpdateKind::Installer => {
            format!("session-password-exporter-{version}-setup-windows-{architecture}.exe")
        }
        UpdateKind::Portable => {
            format!("session-password-exporter-v{version}-portable-windows.zip")
        }
    };
    let checksum_name = format!("session-password-exporter-v{version}-windows.sha256");
    let Ok(download_url) = trusted_asset_url(&release.assets, &asset_name, &release.tag_name)
    else {
        return Ok(None);
    };
    let Ok(checksum_url) = trusted_asset_url(&release.assets, &checksum_name, &release.tag_name)
    else {
        return Ok(None);
    };
    Ok(Some(AvailableUpdate {
        version,
        kind,
        asset_name,
        download_url,
        checksum_name,
        checksum_url,
    }))
}

pub fn checksum_for_file(manifest: &str, file_name: &str) -> Option<String> {
    manifest.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let name = parts.next()?.trim_start_matches('*');
        if hash.len() == 64
            && hash.chars().all(|character| character.is_ascii_hexdigit())
            && name.eq_ignore_ascii_case(file_name)
        {
            Some(hash.to_ascii_lowercase())
        } else {
            None
        }
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn check_for_update(
    current: Version,
    kind: UpdateKind,
    architecture: &str,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    let releases = fetch_text(&format!("{RELEASE_API}/releases?per_page=30"))?;
    select_newer_update(&releases, current, kind, architecture)
}

pub fn download_update(update: &AvailableUpdate) -> Result<PreparedUpdate, UpdateError> {
    let manifest = fetch_text(&update.checksum_url)?;
    let expected = checksum_for_file(&manifest, &update.asset_name).ok_or(UpdateError::Checksum)?;
    let bytes = fetch_bytes(&update.download_url)?;
    if sha256_hex(&bytes) != expected {
        return Err(UpdateError::Checksum);
    }
    let directory = update_directory()?;
    fs::create_dir_all(&directory).map_err(|_| UpdateError::Save)?;
    match update.kind {
        UpdateKind::Installer => {
            let path = directory.join(&update.asset_name);
            write_file(&path, &bytes)?;
            Ok(PreparedUpdate {
                kind: UpdateKind::Installer,
                path,
            })
        }
        UpdateKind::Portable => {
            let executable = extract_portable_executable(&bytes, current_architecture())?;
            let path = directory.join("session-password-exporter.exe");
            write_file(&path, &executable)?;
            Ok(PreparedUpdate {
                kind: UpdateKind::Portable,
                path,
            })
        }
    }
}

pub fn launch_update(prepared: &PreparedUpdate) -> Result<(), UpdateError> {
    match prepared.kind {
        UpdateKind::Installer => spawn_installer(&prepared.path),
        UpdateKind::Portable => spawn_portable_replacement(&prepared.path),
    }
}

pub fn portable_executable_name(architecture: &str) -> String {
    format!("{architecture}/session-password-exporter.exe")
}

fn extract_portable_executable(bytes: &[u8], architecture: &str) -> Result<Vec<u8>, UpdateError> {
    let expected = portable_executable_name(architecture);
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|_| UpdateError::Save)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|_| UpdateError::Save)?;
        let name = entry.name().replace('\\', "/");
        let name = name.trim_start_matches("./");
        if !name.eq_ignore_ascii_case(&expected) {
            continue;
        }
        if entry.size() == 0 || entry.size() > MAX_DOWNLOAD_BYTES {
            return Err(UpdateError::Save);
        }
        let mut executable = Vec::new();
        entry
            .read_to_end(&mut executable)
            .map_err(|_| UpdateError::Save)?;
        return Ok(executable);
    }
    Err(UpdateError::Asset)
}

fn trusted_asset_url(assets: &[GitHubAsset], name: &str, tag: &str) -> Result<String, UpdateError> {
    let asset = assets
        .iter()
        .find(|asset| asset.name.eq_ignore_ascii_case(name))
        .ok_or(UpdateError::Asset)?;
    let expected_prefix = format!("{DOWNLOAD_PREFIX}{tag}/");
    if asset.browser_download_url.starts_with(&expected_prefix)
        && asset.browser_download_url.ends_with(&format!("/{name}"))
    {
        Ok(asset.browser_download_url.clone())
    } else {
        Err(UpdateError::Asset)
    }
}

fn fetch_text(url: &str) -> Result<String, UpdateError> {
    let bytes = fetch_optional_bytes(url)?.ok_or(UpdateError::Network)?;
    String::from_utf8(bytes).map_err(|_| UpdateError::Response)
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>, UpdateError> {
    fetch_optional_bytes(url)?.ok_or(UpdateError::Network)
}

fn fetch_optional_bytes(url: &str) -> Result<Option<Vec<u8>>, UpdateError> {
    let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
    let mut request = agent.get(url).set("User-Agent", USER_AGENT);
    if url.starts_with("https://api.github.com/") {
        request = request.set("Accept", "application/vnd.github+json");
    }
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(_) => return Err(UpdateError::Network),
    };
    let mut reader = response.into_reader().take(MAX_DOWNLOAD_BYTES + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| UpdateError::Network)?;
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(UpdateError::Response);
    }
    Ok(Some(bytes))
}

fn update_directory() -> Result<PathBuf, UpdateError> {
    Ok(std::env::temp_dir().join("session-password-exporter-update"))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), UpdateError> {
    let mut file = fs::File::create(path).map_err(|_| UpdateError::Save)?;
    file.write_all(bytes).map_err(|_| UpdateError::Save)?;
    Ok(())
}

fn spawn_installer(path: &Path) -> Result<(), UpdateError> {
    std::process::Command::new(path)
        .spawn()
        .map(|_| ())
        .map_err(|_| UpdateError::Save)
}

fn spawn_portable_replacement(new_executable: &Path) -> Result<(), UpdateError> {
    let current_executable = std::env::current_exe().map_err(|_| UpdateError::Save)?;
    let script_path = update_directory()?.join("apply-update.cmd");
    let script = portable_replace_script(std::process::id(), new_executable, &current_executable);
    write_file(&script_path, script.as_bytes())?;
    spawn_hidden_command(&script_path)
}

fn portable_replace_script(pid: u32, new_executable: &Path, current_executable: &Path) -> String {
    let new_executable = command_path(new_executable);
    let current_executable = command_path(current_executable);
    format!(
        "@echo off\r\n\
         :wait\r\n\
         tasklist /FI \"PID eq {pid}\" | find \"{pid}\" >nul\r\n\
         if not errorlevel 1 (\r\n\
           ping 127.0.0.1 -n 2 >nul\r\n\
           goto wait\r\n\
         )\r\n\
         :copy\r\n\
         copy /Y \"{new_executable}\" \"{current_executable}\" >nul\r\n\
         if errorlevel 1 (\r\n\
           ping 127.0.0.1 -n 2 >nul\r\n\
           goto copy\r\n\
         )\r\n\
         start \"\" \"{current_executable}\"\r\n\
         del \"%~f0\"\r\n"
    )
}

fn command_path(path: &Path) -> String {
    path.to_string_lossy().replace('%', "%%")
}

fn spawn_hidden_command(script_path: &Path) -> Result<(), UpdateError> {
    let mut command = std::process::Command::new("cmd");
    command.args(["/C", &script_path.to_string_lossy()]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command.spawn().map(|_| ()).map_err(|_| UpdateError::Save)
}

#[derive(Deserialize)]
struct GitHubRelease {
    #[serde(default)]
    name: String,
    #[serde(default)]
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_a_newer_master_release_by_the_version_in_its_title() {
        let current = Version::parse("0.1.1").expect("version");
        let releases = r#"[
            {
                "name": "Session Password Exporter 0.1.3 (master a3fcbb635710)",
                "tag_name": "master-a3fcbb635710",
                "draft": false,
                "prerelease": false,
                "assets": [
                    {
                        "name": "session-password-exporter-0.1.3-setup-windows-x64.exe",
                        "browser_download_url": "https://github.com/EduardRe/SessionPasswordExporter/releases/download/master-a3fcbb635710/session-password-exporter-0.1.3-setup-windows-x64.exe"
                    },
                    {
                        "name": "session-password-exporter-v0.1.3-windows.sha256",
                        "browser_download_url": "https://github.com/EduardRe/SessionPasswordExporter/releases/download/master-a3fcbb635710/session-password-exporter-v0.1.3-windows.sha256"
                    }
                ]
            },
            {
                "name": "Session Password Exporter 0.1.1 (master fc57edd128d7)",
                "tag_name": "master-fc57edd128d7",
                "draft": false,
                "prerelease": false,
                "assets": []
            }
        ]"#;

        let update = select_newer_update(releases, current, UpdateKind::Installer, "x64")
            .expect("releases")
            .expect("newer release");
        assert_eq!(update.version, Version::parse("0.1.3").expect("version"));
        assert!(update.download_url.contains("master-a3fcbb635710"));
        assert_eq!(
            select_newer_update(
                releases,
                Version::parse("0.1.3").expect("version"),
                UpdateKind::Installer,
                "x64"
            )
            .expect("releases"),
            None
        );
    }

    #[test]
    fn reads_the_matching_release_asset_and_rejects_a_foreign_url() {
        let release = r#"{
            "name": "Session Password Exporter 0.1.1",
            "tag_name": "v0.1.1",
            "draft": false,
            "prerelease": false,
            "assets": [
                {
                    "name": "session-password-exporter-0.1.1-setup-windows-x64.exe",
                    "browser_download_url": "https://github.com/EduardRe/SessionPasswordExporter/releases/download/v0.1.1/session-password-exporter-0.1.1-setup-windows-x64.exe"
                },
                {
                    "name": "session-password-exporter-v0.1.1-portable-windows.zip",
                    "browser_download_url": "https://github.com/EduardRe/SessionPasswordExporter/releases/download/v0.1.1/session-password-exporter-v0.1.1-portable-windows.zip"
                },
                {
                    "name": "session-password-exporter-v0.1.1-windows.sha256",
                    "browser_download_url": "https://github.com/EduardRe/SessionPasswordExporter/releases/download/v0.1.1/session-password-exporter-v0.1.1-windows.sha256"
                }
            ]
        }"#;

        let installer = package_from_release(release, UpdateKind::Installer, "x64")
            .expect("release")
            .expect("package");
        assert_eq!(
            installer.asset_name,
            "session-password-exporter-0.1.1-setup-windows-x64.exe"
        );
        let portable = package_from_release(release, UpdateKind::Portable, "x64")
            .expect("release")
            .expect("package");
        assert!(portable.asset_name.ends_with("portable-windows.zip"));

        let foreign = release.replace(
            "https://github.com/EduardRe/SessionPasswordExporter",
            "https://github.com/example/other",
        );
        assert_eq!(
            package_from_release(&foreign, UpdateKind::Installer, "x64").expect("release"),
            None
        );
    }

    #[test]
    fn matches_checksum_lines_and_hashes_bytes() {
        let manifest = "abc123  ignored.exe\n\
            0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  session-password-exporter-v0.1.1-portable-windows.zip\n";
        assert_eq!(
            checksum_for_file(
                manifest,
                "session-password-exporter-v0.1.1-portable-windows.zip"
            )
            .as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn portable_script_waits_for_the_process_and_restarts_the_same_executable() {
        let script = portable_replace_script(
            42,
            Path::new(r"C:\Temp\new.exe"),
            Path::new(r"C:\Portable\x64\session-password-exporter.exe"),
        );
        assert!(script.contains("PID eq 42"));
        assert!(script.contains(r"C:\Portable\x64\session-password-exporter.exe"));
        assert!(script.contains("start \"\""));
    }
}
