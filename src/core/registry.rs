#[cfg(not(windows))]
use crate::config::constants::STATUS_UNSUPPORTED_PLATFORM;
use crate::core::model::ImportReport;

#[cfg(windows)]
pub fn load_registry_sessions() -> Result<ImportReport, String> {
    use std::collections::BTreeMap;

    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    use crate::config::constants::{
        ERROR_READ_REGISTRY, REGISTRY_BASE_PATH, REGISTRY_DEFAULT_SETTINGS,
        REGISTRY_MASTER_PASSWORD_VERIFIER, REGISTRY_SECURITY_KEY, REGISTRY_SESSIONS_KEY,
        REGISTRY_USE_MASTER_PASSWORD,
    };
    use crate::core::parser::{
        MasterPasswordConfig, percent_decode, read_connection, session_from_values,
    };

    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    let root = current_user
        .open_subkey(REGISTRY_BASE_PATH)
        .map_err(|_| ERROR_READ_REGISTRY.to_owned())?;
    let (master_password_enabled, master_password_verifier) = root
        .open_subkey(REGISTRY_SECURITY_KEY)
        .ok()
        .map(|security| {
            (
                security
                    .get_value::<u32, _>(REGISTRY_USE_MASTER_PASSWORD)
                    .is_ok_and(|value| value != 0),
                security
                    .get_value::<String, _>(REGISTRY_MASTER_PASSWORD_VERIFIER)
                    .ok()
                    .filter(|value| !value.is_empty()),
            )
        })
        .unwrap_or((false, None));
    let master_password = MasterPasswordConfig {
        enabled: master_password_enabled,
        verifier: master_password_verifier,
    };
    let sessions_key = root
        .open_subkey(REGISTRY_SESSIONS_KEY)
        .map_err(|_| ERROR_READ_REGISTRY.to_owned())?;

    let mut report = ImportReport::default();
    walk_registry_sessions(&sessions_key, &mut Vec::new(), master_password, &mut report);

    fn walk_registry_sessions(
        key: &RegKey,
        folder_path: &mut Vec<String>,
        master_password: MasterPasswordConfig,
        report: &mut ImportReport,
    ) {
        for child_name in key.enum_keys().flatten() {
            if child_name.eq_ignore_ascii_case(REGISTRY_DEFAULT_SETTINGS) {
                continue;
            }
            let Ok(child) = key.open_subkey(&child_name) else {
                continue;
            };
            let values = registry_values(&child);

            let host = values.get("hostname").cloned().unwrap_or_default();
            let username = values.get("username").cloned().unwrap_or_default();
            let encrypted_password = values.get("password").cloned();
            let (connection, port) = read_connection(&values);
            let is_session = values.contains_key("hostname")
                || values.contains_key("username")
                || values.contains_key("password");

            if is_session {
                let name = percent_decode(&child_name);
                let source = format!("HKCU\\{}\\{}", REGISTRY_BASE_PATH, REGISTRY_SESSIONS_KEY);
                report.sessions.push(session_from_values(
                    name,
                    folder_path.clone(),
                    host,
                    port,
                    connection,
                    username,
                    encrypted_password,
                    master_password.clone(),
                    source,
                ));
            } else {
                folder_path.push(percent_decode(&child_name));
                walk_registry_sessions(&child, folder_path, master_password.clone(), report);
                folder_path.pop();
            }
        }
    }

    fn registry_values(key: &RegKey) -> BTreeMap<String, String> {
        key.enum_values()
            .flatten()
            .filter_map(|(name, _)| {
                registry_value_string(key, &name).map(|value| (name.to_ascii_lowercase(), value))
            })
            .collect()
    }

    fn registry_value_string(key: &RegKey, name: &str) -> Option<String> {
        if let Ok(value) = key.get_value::<String, _>(name) {
            return Some(value);
        }
        key.get_value::<u32, _>(name)
            .ok()
            .map(|value| value.to_string())
    }

    Ok(report)
}

#[cfg(not(windows))]
pub fn load_registry_sessions() -> Result<ImportReport, String> {
    Err(STATUS_UNSUPPORTED_PLATFORM.to_owned())
}

#[cfg(test)]
mod tests {
    use crate::core::model::LanguagePreference;

    #[test]
    fn registry_source_is_platform_gated_and_language_preferences_are_cross_platform() {
        assert_eq!(LanguagePreference::default(), LanguagePreference::System);
        #[cfg(not(windows))]
        assert!(super::load_registry_sessions().is_err());
    }
}
