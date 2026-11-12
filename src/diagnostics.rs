use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::constants::{
    DIAGNOSTICS_DIRECTORY_NAME, DIAGNOSTICS_ERROR_TITLE, DIAGNOSTICS_LOG_FILENAME,
    DIAGNOSTICS_LOG_HEADER, DIAGNOSTICS_LOG_NOTICE,
};

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn initialize() {
    let _ = append_line(DIAGNOSTICS_LOG_HEADER);
    let _ = append_line(DIAGNOSTICS_LOG_NOTICE);
    record("GUI process started");
    std::panic::set_hook(Box::new(|panic| {
        let location = panic
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()))
            .unwrap_or_else(|| "unknown location".to_owned());
        record(&format!("Panic at {location}: {panic}"));
        record(&format!(
            "Backtrace:\n{}",
            std::backtrace::Backtrace::force_capture()
        ));
    }));
}

pub fn record(event: &str) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "unknown-time".to_owned());
    let _ = append_line(&format!("[{timestamp}] {event}"));
}

pub fn log_path() -> Option<PathBuf> {
    LOG_PATH.get().cloned().or_else(resolve_log_path)
}

pub fn report_startup_error(error: &str) {
    record(&format!("Startup failed: {error}"));
    let message = match log_path() {
        Some(path) => format!("{error}\n\nDiagnostic log: {}", path.display()),
        None => format!("{error}\n\nCould not create the diagnostic log."),
    };
    show_error_dialog(&message);
}

fn append_line(line: &str) -> std::io::Result<()> {
    let path = LOG_PATH.get_or_init(|| resolve_log_path().unwrap_or_default());
    if path.as_os_str().is_empty() {
        return Err(std::io::Error::other("no writable log directory"));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}

fn resolve_log_path() -> Option<PathBuf> {
    let executable_directory = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let beside_executable = executable_directory.join(DIAGNOSTICS_LOG_FILENAME);
    if ensure_writable(&beside_executable) {
        return Some(beside_executable);
    }

    let local_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)?;
    let fallback = local_data
        .join(DIAGNOSTICS_DIRECTORY_NAME)
        .join(DIAGNOSTICS_LOG_FILENAME);
    ensure_writable(&fallback).then_some(fallback)
}

fn ensure_writable(path: &PathBuf) -> bool {
    path.parent()
        .is_some_and(|parent| fs::create_dir_all(parent).is_ok())
        && OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .is_ok()
}

#[cfg(windows)]
fn show_error_dialog(message: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

    let title = std::ffi::OsStr::new(DIAGNOSTICS_ERROR_TITLE)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let message = std::ffi::OsStr::new(message)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(not(windows))]
fn show_error_dialog(message: &str) {
    eprintln!("{DIAGNOSTICS_ERROR_TITLE}: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_file_name_is_specific_to_the_application() {
        assert_eq!(DIAGNOSTICS_LOG_FILENAME, "startup.log");
    }

    #[test]
    fn fallback_log_path_uses_local_app_data_when_available() {
        let directory = std::env::temp_dir().join(format!(
            "session-password-exporter-diagnostics-test-{}",
            std::process::id()
        ));
        let path = directory.join(DIAGNOSTICS_LOG_FILENAME);
        assert!(ensure_writable(&path));
        assert!(path.exists());
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
}
