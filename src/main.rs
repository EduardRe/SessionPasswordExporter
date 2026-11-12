#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

use std::ffi::OsString;

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();

    #[cfg(windows)]
    if should_attach_console(&args) {
        // GUI-subsystem executables must attach to the invoking terminal before
        // Clap or std::io initializes its output handles.
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(
                windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS,
            );
        }
    }

    let gui_launch = !should_attach_console(&args);
    if gui_launch {
        session_password_exporter::diagnostics::initialize();
    }

    if let Err(error) = session_password_exporter::cli::run() {
        if gui_launch {
            session_password_exporter::diagnostics::report_startup_error(&error);
        }
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn should_attach_console(args: &[OsString]) -> bool {
    !args.is_empty() && !args.iter().any(|arg| arg.to_str() == Some("--gui"))
}

#[cfg(test)]
mod tests {
    use super::should_attach_console;
    use std::ffi::OsString;

    #[test]
    fn does_not_attach_a_console_for_default_gui_launch() {
        assert!(!should_attach_console(&[]));
    }

    #[test]
    fn does_not_attach_a_console_when_gui_is_requested() {
        assert!(!should_attach_console(&[OsString::from("--gui")]));
    }

    #[test]
    fn attaches_to_the_parent_console_for_cli_arguments() {
        assert!(should_attach_console(&[OsString::from("--help")]));
        assert!(should_attach_console(&[OsString::from("sessions.ini")]));
    }
}
