use std::fs;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::constants::{CONFIG_EXTENSION, ERROR_NOT_INI, ERROR_READ_INPUT};
use crate::core::model::ImportReport;
use crate::core::parser::parse_ini_bytes;

#[cfg(test)]
static TEMP_DIRECTORY_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn load_ini_inputs(inputs: &[PathBuf]) -> ImportReport {
    let mut report = ImportReport::default();
    let mut files = Vec::new();

    for input in inputs {
        match collect_input(input, &mut files) {
            Ok(()) => {}
            Err(message) => report.warnings.push(message),
        }
    }
    files.sort();
    files.dedup();

    for path in files {
        match fs::read(&path) {
            Ok(contents) => {
                let source = path.to_string_lossy().into_owned();
                report.append(parse_ini_bytes(&contents, &source));
            }
            Err(error) => report
                .warnings
                .push(format!("{ERROR_READ_INPUT} {}: {error}", path.display())),
        }
    }
    report
}

fn collect_input(input: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(input)
        .map_err(|error| format!("{ERROR_READ_INPUT} {}: {error}", input.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{ERROR_READ_INPUT} {}", input.display()));
    }
    if metadata.is_file() {
        if has_ini_extension(input) {
            output.push(input.to_path_buf());
            return Ok(());
        }
        return Err(format!("{ERROR_NOT_INI} {}", input.display()));
    }
    if !metadata.is_dir() {
        return Err(format!("{ERROR_READ_INPUT} {}", input.display()));
    }

    collect_directory(input, output)
}

fn collect_directory(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("{ERROR_READ_INPUT} {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("{ERROR_READ_INPUT} {}: {error}", directory.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("{ERROR_READ_INPUT} {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_directory(&path, output)?;
        } else if file_type.is_file() && has_ini_extension(&path) {
            output.push(path);
        }
    }
    Ok(())
}

fn has_ini_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(CONFIG_EXTENSION))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "{}-{}-{id}",
                crate::config::constants::APP_ID,
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_session(path: &Path, name: &str, host: &str) {
        fs::write(
            path,
            format!("[Sessions\\{name}]\nHostName={host}\nUserName=tester\n"),
        )
        .expect("write test config");
    }

    #[test]
    fn loads_multiple_ini_files_recursively_and_ignores_other_files() {
        let directory = TestDirectory::new();
        let nested = directory.path().join("nested");
        fs::create_dir_all(&nested).expect("create nested directory");
        write_session(&directory.path().join("one.ini"), "One", "one.example.test");
        write_session(&nested.join("two.INI"), "Two", "two.example.test");
        fs::write(directory.path().join("notes.txt"), "not a config").expect("write text file");

        let report = load_ini_inputs(&[directory.path().to_path_buf()]);
        assert_eq!(report.sessions.len(), 2);
        let mut names = report
            .sessions
            .iter()
            .map(|session| session.name.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, ["One", "Two"]);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn reports_non_ini_files_without_parsing_them() {
        let directory = TestDirectory::new();
        let text_file = directory.path().join("not-ini.txt");
        fs::write(&text_file, "contents").expect("write text file");
        let report = load_ini_inputs(&[text_file]);
        assert!(report.sessions.is_empty());
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains(ERROR_NOT_INI));
    }

    #[test]
    fn combines_several_explicit_files() {
        let directory = TestDirectory::new();
        let first = directory.path().join("first.ini");
        let second = directory.path().join("second.ini");
        write_session(&first, "First", "first.example.test");
        write_session(&second, "Second", "second.example.test");
        let report = load_ini_inputs(&[second, first]);
        assert_eq!(report.sessions.len(), 2);
        assert_eq!(report.sessions[0].name, "First");
        assert_eq!(report.sessions[1].name, "Second");
    }
}
