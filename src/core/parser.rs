use std::collections::BTreeMap;

use crate::config::constants::{
    INI_FS_PROTOCOL, INI_FTPS, INI_HOST_NAME, INI_MASTER_PASSWORD_VERIFIER, INI_PASSWORD,
    INI_PORT_NUMBER, INI_SECURITY_SECTION, INI_SESSION_NAME, INI_SESSIONS_PREFIX,
    INI_USE_MASTER_PASSWORD, INI_USER_NAME, REGISTRY_DEFAULT_SETTINGS,
};
use crate::core::crypto::decrypt_password;
use crate::core::model::{
    ConnectionKind, ImportReport, PasswordStatus, SecretString, Session, resolve_port,
};

#[derive(Clone, Default)]
pub struct MasterPasswordConfig {
    pub enabled: bool,
    pub verifier: Option<String>,
}

pub fn parse_ini_bytes(bytes: &[u8], source: &str) -> ImportReport {
    parse_ini_text(&decode_ini_bytes(bytes), source)
}

pub fn parse_ini_text(contents: &str, source: &str) -> ImportReport {
    let sections = parse_sections(contents);
    let master_password = sections
        .iter()
        .find(|(section, _)| section.eq_ignore_ascii_case(INI_SECURITY_SECTION))
        .map(|(_, values)| MasterPasswordConfig {
            enabled: values
                .get(INI_USE_MASTER_PASSWORD)
                .is_some_and(|value| is_enabled(value)),
            verifier: values
                .get(INI_MASTER_PASSWORD_VERIFIER)
                .filter(|value| !value.is_empty())
                .cloned(),
        })
        .unwrap_or_default();

    let mut report = ImportReport::default();
    for (section, values) in sections {
        let normalized_section = section.replace('/', "\\");
        let Some(session_path) = strip_ascii_case_prefix(&normalized_section, INI_SESSIONS_PREFIX)
        else {
            continue;
        };
        let parts = session_path
            .split('\\')
            .filter(|part| !part.is_empty())
            .map(percent_decode)
            .collect::<Vec<_>>();
        let Some(name_from_section) = parts.last() else {
            continue;
        };
        if parts.len() == 1 && name_from_section.eq_ignore_ascii_case(REGISTRY_DEFAULT_SETTINGS) {
            continue;
        }

        let name = values
            .get(INI_SESSION_NAME)
            .filter(|value| !value.is_empty())
            .map(|value| percent_decode(value))
            .unwrap_or_else(|| name_from_section.clone());
        let host = values
            .get(INI_HOST_NAME)
            .map(|value| percent_decode(value))
            .unwrap_or_default();
        let username = values
            .get(INI_USER_NAME)
            .map(|value| percent_decode(value))
            .unwrap_or_default();
        let encrypted_password = values.get(INI_PASSWORD).map(|value| percent_decode(value));
        let (connection, port) = read_connection(&values);
        let folder = parts[..parts.len().saturating_sub(1)].to_vec();

        report.sessions.push(session_from_values(
            name,
            folder,
            host,
            port,
            connection,
            username,
            encrypted_password,
            master_password.clone(),
            source.to_owned(),
        ));
    }
    report
}

pub fn read_connection(values: &BTreeMap<String, String>) -> (ConnectionKind, u16) {
    let protocol = values
        .get(INI_FS_PROTOCOL)
        .and_then(|value| parse_integer(value));
    let ftps = values
        .get(INI_FTPS)
        .and_then(|value| parse_integer(value))
        .unwrap_or(0);
    let stored_port = values
        .get(INI_PORT_NUMBER)
        .and_then(|value| parse_integer(value));
    let connection = ConnectionKind::from_winscp(protocol, ftps);
    (connection, resolve_port(connection, ftps, stored_port))
}

fn parse_integer(value: &str) -> Option<u32> {
    value.trim().parse().ok()
}

#[allow(clippy::too_many_arguments)]
pub fn session_from_values(
    name: String,
    folder: Vec<String>,
    host: String,
    port: u16,
    connection: ConnectionKind,
    username: String,
    encrypted_password: Option<String>,
    master_password: MasterPasswordConfig,
    source: String,
) -> Session {
    let (password, password_status, encrypted_password) = match encrypted_password.as_deref() {
        None | Some("") => (String::new(), PasswordStatus::NotStored, None),
        Some(encrypted) if crate::core::crypto::is_master_password_encoded(encrypted) => (
            String::new(),
            PasswordStatus::MasterPasswordProtected,
            Some(SecretString::new(encrypted.to_owned())),
        ),
        Some(encrypted) if master_password.enabled => {
            match decrypt_password(encrypted, &format!("{username}{host}")) {
                Ok(password) => (password, PasswordStatus::Available, None),
                Err(_) => (
                    String::new(),
                    PasswordStatus::MasterPasswordProtected,
                    Some(SecretString::new(encrypted.to_owned())),
                ),
            }
        }
        Some(encrypted) => {
            let session_key = format!("{username}{host}");
            match decrypt_password(encrypted, &session_key) {
                Ok(password) => (password, PasswordStatus::Available, None),
                Err(_) => (String::new(), PasswordStatus::CouldNotDecrypt, None),
            }
        }
    };

    Session {
        name,
        host,
        port,
        connection,
        username,
        folder,
        password: SecretString::new(password),
        encrypted_password,
        master_password_verifier: master_password.verifier.map(SecretString::new),
        password_status,
        source,
    }
}

fn parse_sections(contents: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut sections = Vec::new();
    let mut current: Option<(String, BTreeMap<String, String>)> = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim().trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            current = Some((line[1..line.len() - 1].trim().to_owned(), BTreeMap::new()));
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if let Some((_, values)) = current.as_mut() {
            values.insert(key.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    if let Some(section) = current {
        sections.push(section);
    }
    sections
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn is_enabled(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES")
}

fn decode_ini_bytes(bytes: &[u8]) -> String {
    const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
    const UTF16_LE_BOM: &[u8] = &[0xFF, 0xFE];
    const UTF16_BE_BOM: &[u8] = &[0xFE, 0xFF];

    if let Some(text) = bytes.strip_prefix(UTF8_BOM) {
        return String::from_utf8_lossy(text).into_owned();
    }
    if let Some(text) = bytes.strip_prefix(UTF16_LE_BOM) {
        return String::from_utf16_lossy(
            &text
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect::<Vec<_>>(),
        );
    }
    if let Some(text) = bytes.strip_prefix(UTF16_BE_BOM) {
        return String::from_utf16_lossy(
            &text
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect::<Vec<_>>(),
        );
    }
    String::from_utf8_lossy(bytes).into_owned()
}

pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded)
        .trim_start_matches('\u{FEFF}')
        .to_owned()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{ConnectionKind, PasswordStatus};

    const BASIC_INI: &str =
        "[Sessions\\Team\\Production]\nHostName=prod.example.test\nUserName=deploy\n";
    const ESCAPED_INI: &str = "[Sessions\\Engineering%20Sites\\Web%20Prod]\nHostName=host%2Eexample%2Etest\nUserName=web%40example\n";
    const DEFAULT_SETTINGS_INI: &str = "[Sessions\\Default Settings]\nHostName=default.example.test\n[Sessions\\Actual]\nHostName=actual.example.test\n";
    const MASTER_PASSWORD_INI: &str = "[Configuration\\Security]\nUseMasterPassword=1\n[Sessions\\Protected]\nHostName=secure.example.test\nUserName=admin\nPassword=0011\n";

    #[test]
    fn reads_session_fields_and_nested_folder_paths() {
        let report = parse_ini_text(BASIC_INI, "sample.ini");
        assert_eq!(report.sessions.len(), 1);
        assert_eq!(report.sessions[0].name, "Production");
        assert_eq!(report.sessions[0].folder, ["Team"]);
        assert_eq!(report.sessions[0].host, "prod.example.test");
        assert_eq!(report.sessions[0].username, "deploy");
        assert_eq!(report.sessions[0].connection, ConnectionKind::Sftp);
        assert_eq!(report.sessions[0].port, 22);
        assert_eq!(
            report.sessions[0].password_status,
            PasswordStatus::NotStored
        );
    }

    #[test]
    fn reads_protocol_and_port_using_winscp_defaults() {
        let ini = "\
[Sessions\\Scp]\nHostName=scp.example.test\nFSProtocol=0\n\
[Sessions\\Ftp]\nHostName=ftp.example.test\nFSProtocol=5\nPortNumber=2121\n\
[Sessions\\FtpDefault]\nHostName=ftp-default.example.test\nFSProtocol=5\n\
[Sessions\\Ftps]\nHostName=ftps.example.test\nFSProtocol=5\nFtps=1\n\
[Sessions\\Ftpes]\nHostName=ftpes.example.test\nFSProtocol=5\nFtps=3\n\
[Sessions\\Dav]\nHostName=dav.example.test\nFSProtocol=6\n\
[Sessions\\Davs]\nHostName=davs.example.test\nFSProtocol=6\nFtps=1\nPortNumber=8443\n\
[Sessions\\Bucket]\nHostName=s3.example.test\nFSProtocol=7\nFtps=1\n\
[Sessions\\CustomSftp]\nHostName=only.example.test\nFSProtocol=2\nPortNumber=2222\n\
[Sessions\\IgnoredPort]\nHostName=zero.example.test\nFSProtocol=5\nPortNumber=0\n";
        let report = parse_ini_text(ini, "protocols.ini");
        let session = |name: &str| {
            report
                .sessions
                .iter()
                .find(|session| session.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
        };

        assert_eq!(session("Scp").connection, ConnectionKind::Scp);
        assert_eq!(session("Scp").port, 22);
        assert_eq!(session("Ftp").connection, ConnectionKind::Ftp);
        assert_eq!(session("Ftp").port, 2121);
        assert_eq!(session("FtpDefault").connection, ConnectionKind::Ftp);
        assert_eq!(session("FtpDefault").port, 21);
        assert_eq!(session("Ftps").connection, ConnectionKind::Ftps);
        assert_eq!(session("Ftps").port, 990);
        assert_eq!(session("Ftpes").connection, ConnectionKind::Ftpes);
        assert_eq!(session("Ftpes").port, 21);
        assert_eq!(session("Dav").connection, ConnectionKind::WebDav);
        assert_eq!(session("Dav").port, 80);
        assert_eq!(session("Davs").connection, ConnectionKind::WebDavs);
        assert_eq!(session("Davs").port, 8443);
        assert_eq!(session("Bucket").connection, ConnectionKind::S3);
        assert_eq!(session("Bucket").port, 443);
        assert_eq!(session("CustomSftp").connection, ConnectionKind::Sftp);
        assert_eq!(session("CustomSftp").port, 2222);
        assert_eq!(session("IgnoredPort").port, 21);
    }

    #[test]
    fn percent_decodes_ini_names_hosts_and_usernames() {
        let report = parse_ini_text(ESCAPED_INI, "sample.ini");
        assert_eq!(report.sessions[0].folder, ["Engineering Sites"]);
        assert_eq!(report.sessions[0].name, "Web Prod");
        assert_eq!(report.sessions[0].host, "host.example.test");
        assert_eq!(report.sessions[0].username, "web@example");
    }

    #[test]
    fn skips_default_session_settings() {
        let report = parse_ini_text(DEFAULT_SETTINGS_INI, "sample.ini");
        assert_eq!(report.sessions.len(), 1);
        assert_eq!(report.sessions[0].name, "Actual");
    }

    #[test]
    fn marks_master_password_sessions_as_protected() {
        let report = parse_ini_text(MASTER_PASSWORD_INI, "sample.ini");
        assert_eq!(
            report.sessions[0].password_status,
            PasswordStatus::MasterPasswordProtected
        );
        assert!(report.sessions[0].password.is_empty());
        assert_eq!(
            report.sessions[0]
                .encrypted_password
                .as_ref()
                .map(SecretString::as_str),
            Some("0011")
        );
    }

    #[test]
    fn parses_master_password_verifier_and_retains_wrapped_ciphertext() {
        let verifier = crate::core::crypto::tests_support::create_test_verifier("correct");
        let encrypted = crate::core::crypto::tests_support::encrypt_test_master_password(
            "secret value",
            "correct",
        );
        let config = format!(
            "[Configuration\\Security]\nUseMasterPassword=1\nMasterPasswordVerifier={verifier}\n[Sessions\\Protected]\nHostName=secure.example.test\nUserName=admin\nPassword={encrypted}\n"
        );
        let mut report = parse_ini_text(&config, "master.ini");
        let session = report.sessions.pop().expect("parsed session");
        assert_eq!(
            session
                .encrypted_password
                .as_ref()
                .map(SecretString::as_str),
            Some(encrypted.as_str())
        );
        assert_eq!(
            session
                .master_password_verifier
                .as_ref()
                .map(SecretString::as_str),
            Some(verifier.as_str())
        );

        let mut sessions = [session];
        assert!(crate::core::master_password::unlock_protected_source(
            &mut sessions,
            "master.ini",
            "correct"
        ));
        assert_eq!(sessions[0].password.as_str(), "secret value");
    }

    #[test]
    fn decodes_utf8_and_utf16_bom_files() {
        const UTF8_BYTES: &[u8] = b"\xEF\xBB\xBF[Sessions\\One]\nHostName=one.test\n";
        let utf8 = parse_ini_bytes(UTF8_BYTES, "utf8.ini");
        assert_eq!(utf8.sessions[0].host, "one.test");

        let text = "[Sessions\\Two]\r\nHostName=two.test\r\n";
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let utf16_report = parse_ini_bytes(&utf16, "utf16.ini");
        assert_eq!(utf16_report.sessions[0].host, "two.test");
    }

    #[test]
    fn leaves_invalid_percent_sequences_untouched() {
        assert_eq!(percent_decode("name%2X%"), "name%2X%");
    }

    #[test]
    fn removes_a_leading_byte_order_mark_from_imported_names() {
        assert_eq!(percent_decode("\u{FEFF}TEMP"), "TEMP");
        assert_eq!(percent_decode("%EF%BB%BFTEMP"), "TEMP");
    }
}
