use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::config::constants::{
    APP_ID, APP_ORGANIZATION, APP_QUALIFIER, ENV_APPDATA, ENV_XDG_CONFIG_HOME,
    PORTABLE_DATA_DIRECTORY, PORTABLE_MODE_MARKER, SETTINGS_FILE_NAME, SETTINGS_TEMP_EXTENSION,
    STATUS_INVALID_SETTINGS, STATUS_SETTINGS_WRITE_FAILED,
};
use crate::core::model::Settings;

pub fn load_settings() -> (Settings, Option<String>) {
    let portable_path = portable_settings_path();
    let path = portable_path.clone().unwrap_or_else(user_settings_path);

    if let Some(portable_path) = portable_path
        && let Err(error) = migrate_legacy_settings(&user_settings_path(), &portable_path)
    {
        return (Settings::default(), Some(error));
    }

    match load_settings_from_path(&path) {
        Ok(settings) => (settings, None),
        Err(_) => (
            Settings::default(),
            Some(STATUS_INVALID_SETTINGS.to_owned()),
        ),
    }
}

pub fn save_settings(settings: &Settings) -> Result<(), String> {
    save_settings_to_path(settings, &settings_path())
}

pub fn settings_path() -> PathBuf {
    portable_settings_path().unwrap_or_else(user_settings_path)
}

fn portable_settings_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| portable_settings_path_for_executable(&path))
}

fn portable_settings_path_for_executable(executable_path: &Path) -> Option<PathBuf> {
    let executable_directory = executable_path.parent()?;
    let portable_root = if executable_directory.join(PORTABLE_MODE_MARKER).is_file() {
        executable_directory
    } else {
        let parent_directory = executable_directory.parent()?;
        parent_directory
            .join(PORTABLE_MODE_MARKER)
            .is_file()
            .then_some(parent_directory)?
    };
    Some(
        portable_root
            .join(PORTABLE_DATA_DIRECTORY)
            .join(SETTINGS_FILE_NAME),
    )
}

fn user_settings_path() -> PathBuf {
    if let Some(project_dirs) = ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, APP_ID) {
        return project_dirs.config_dir().join(SETTINGS_FILE_NAME);
    }

    let root = std::env::var_os(ENV_APPDATA)
        .or_else(|| std::env::var_os(ENV_XDG_CONFIG_HOME))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    root.join(APP_ID).join(SETTINGS_FILE_NAME)
}

fn migrate_legacy_settings(source: &Path, portable_path: &Path) -> Result<(), String> {
    if portable_path.exists() || !source.exists() {
        return Ok(());
    }

    let settings = load_settings_from_path(source)?;
    save_settings_to_path(&settings, portable_path)
}

fn load_settings_from_path(path: &Path) -> Result<Settings, String> {
    if !path.exists() {
        return Ok(Settings::default());
    }
    let contents = fs::read(path).map_err(|_| STATUS_SETTINGS_WRITE_FAILED.to_owned())?;
    serde_json::from_slice(&contents).map_err(|_| STATUS_INVALID_SETTINGS.to_owned())
}

fn save_settings_to_path(settings: &Settings, path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| STATUS_SETTINGS_WRITE_FAILED.to_owned())?;
    fs::create_dir_all(parent).map_err(|_| STATUS_SETTINGS_WRITE_FAILED.to_owned())?;

    let mut temporary_path = path.to_path_buf();
    temporary_path.set_extension(SETTINGS_TEMP_EXTENSION);
    let data =
        serde_json::to_vec_pretty(settings).map_err(|_| STATUS_SETTINGS_WRITE_FAILED.to_owned())?;
    fs::write(&temporary_path, data).map_err(|_| STATUS_SETTINGS_WRITE_FAILED.to_owned())?;
    if path.exists() {
        fs::remove_file(path).map_err(|_| STATUS_SETTINGS_WRITE_FAILED.to_owned())?;
    }
    fs::rename(&temporary_path, path).map_err(|_| STATUS_SETTINGS_WRITE_FAILED.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{
        LanguagePreference, PasswordClickAction, RecoverySearchSettings, ThemePreference,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_settings_path() -> PathBuf {
        let id = TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("{}-settings-{}-{id}", APP_ID, std::process::id()))
            .join(SETTINGS_FILE_NAME)
    }

    fn test_settings() -> Settings {
        Settings {
            password_click_action: PasswordClickAction::Copy,
            language: LanguagePreference::English,
            theme: ThemePreference::Light,
            exclude_collapsed_from_search: true,
            recovery_search: RecoverySearchSettings {
                minimum_length: 2,
                maximum_length: 11,
                digits: false,
                letters: true,
                symbols: true,
            },
        }
    }

    #[test]
    fn defaults_to_system_language_show_copy_action_and_searches_collapsed_lists() {
        let settings = Settings::default();
        assert_eq!(settings.language, LanguagePreference::System);
        assert_eq!(settings.theme, ThemePreference::System);
        assert_eq!(
            settings.password_click_action,
            PasswordClickAction::ShowAndCopy
        );
        assert!(!settings.exclude_collapsed_from_search);
        assert_eq!(settings.recovery_search, RecoverySearchSettings::default());
    }

    #[test]
    fn saves_and_loads_all_settings() {
        let path = test_settings_path();
        let settings = test_settings();
        save_settings_to_path(&settings, &path).expect("save settings");
        assert_eq!(
            load_settings_from_path(&path).expect("load settings"),
            settings
        );
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn missing_settings_file_uses_defaults() {
        let path = test_settings_path();
        let _ = fs::remove_file(&path);
        assert_eq!(
            load_settings_from_path(&path).expect("missing settings"),
            Settings::default()
        );
    }

    #[test]
    fn old_settings_without_new_fields_keep_their_defaults() {
        let legacy = br#"{"password_click_action":"copy","language":"english"}"#;
        let settings: Settings = serde_json::from_slice(legacy).expect("legacy settings");
        assert_eq!(settings.theme, ThemePreference::System);
        assert!(!settings.exclude_collapsed_from_search);
        assert_eq!(settings.recovery_search, RecoverySearchSettings::default());
    }

    #[test]
    fn portable_marker_selects_a_settings_file_next_to_the_executable() {
        let executable = test_settings_path()
            .parent()
            .expect("test directory")
            .join("session-password-exporter.exe");
        let executable_directory = executable.parent().expect("executable directory");
        fs::create_dir_all(executable_directory).expect("create executable directory");
        fs::write(executable_directory.join(PORTABLE_MODE_MARKER), b"portable")
            .expect("write portable marker");

        assert_eq!(
            portable_settings_path_for_executable(&executable),
            Some(
                executable_directory
                    .join(PORTABLE_DATA_DIRECTORY)
                    .join(SETTINGS_FILE_NAME)
            )
        );

        let _ = fs::remove_dir_all(executable_directory);
    }

    #[test]
    fn portable_marker_at_archive_root_shares_settings_between_architecture_folders() {
        let portable_root = test_settings_path()
            .parent()
            .expect("test directory")
            .to_path_buf();
        let architecture_directory = portable_root.join("x86");
        let executable = architecture_directory.join("session-password-exporter.exe");
        fs::create_dir_all(&architecture_directory).expect("create architecture directory");
        fs::write(portable_root.join(PORTABLE_MODE_MARKER), b"portable")
            .expect("write portable marker");

        assert_eq!(
            portable_settings_path_for_executable(&executable),
            Some(
                portable_root
                    .join(PORTABLE_DATA_DIRECTORY)
                    .join(SETTINGS_FILE_NAME)
            )
        );

        let _ = fs::remove_dir_all(portable_root);
    }

    #[test]
    fn missing_portable_marker_uses_the_regular_settings_location() {
        let executable = test_settings_path()
            .parent()
            .expect("test directory")
            .join("session-password-exporter.exe");
        assert_eq!(portable_settings_path_for_executable(&executable), None);
    }

    #[test]
    fn migrates_user_settings_once_to_the_portable_directory() {
        let source = test_settings_path();
        let portable_path = source
            .parent()
            .expect("test directory")
            .join(PORTABLE_DATA_DIRECTORY)
            .join(SETTINGS_FILE_NAME);
        let settings = test_settings();
        save_settings_to_path(&settings, &source).expect("save source settings");

        migrate_legacy_settings(&source, &portable_path).expect("migrate settings");
        assert_eq!(
            load_settings_from_path(&portable_path).expect("load portable settings"),
            settings
        );

        let replacement = Settings::default();
        save_settings_to_path(&replacement, &source).expect("replace source settings");
        migrate_legacy_settings(&source, &portable_path).expect("keep portable settings");
        assert_eq!(
            load_settings_from_path(&portable_path).expect("load portable settings"),
            settings
        );

        if let Some(parent) = source.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn portable_mode_without_existing_user_settings_keeps_defaults() {
        let source = test_settings_path();
        let portable_path = source
            .parent()
            .expect("test directory")
            .join(PORTABLE_DATA_DIRECTORY)
            .join(SETTINGS_FILE_NAME);

        migrate_legacy_settings(&source, &portable_path).expect("skip missing source");
        assert!(!portable_path.exists());

        if let Some(parent) = source.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}
