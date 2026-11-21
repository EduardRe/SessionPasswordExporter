use serde::Serialize;

use crate::config::localization::{Language, labels};
use crate::core::grouping::{SessionGroup, group_session_indices};
use crate::core::model::{ExportFormat, Session};

pub fn export_sessions(sessions: &[Session], format: ExportFormat, language: Language) -> String {
    match format {
        ExportFormat::Text => export_text(sessions, language),
        ExportFormat::Json => export_json(sessions),
        ExportFormat::Xml => export_xml(sessions),
    }
}

fn export_text(sessions: &[Session], language: Language) -> String {
    let text = labels(language);
    let mut blocks = Vec::new();
    for group in session_groups(sessions) {
        blocks.push(format!(
            "{}: {}",
            text.text_source,
            group.localized_name(language)
        ));
        blocks.extend(
            group
                .session_indices
                .iter()
                .map(|&index| export_text_session(&sessions[index], language)),
        );
    }
    blocks.join("\n\n")
}

fn export_text_session(session: &Session, language: Language) -> String {
    let text = labels(language);
    let mut lines = vec![format!("{}: {}", text.text_session, session.name)];
    if !session.folder.is_empty() {
        lines.push(format!(
            "{}: {}",
            text.text_folder,
            session.folder.join("/")
        ));
    }
    lines.push(format!("{}: {}", text.text_host, session.host));
    lines.push(format!("{}: {}", text.text_port, session.port));
    lines.push(format!("{}: {}", text.text_user, session.username));
    let password = if session.password_status == crate::core::model::PasswordStatus::Available {
        session.password.as_str()
    } else {
        session.password_status.localized_label(language)
    };
    lines.push(format!("{}: {password}", text.text_password));
    lines.push(format!("{}: {}", text.text_source, session.source));
    lines.join("\n")
}

#[derive(Serialize)]
struct ExportedSession<'a> {
    name: &'a str,
    folder: &'a [String],
    host: &'a str,
    port: u16,
    username: &'a str,
    password: Option<&'a str>,
    password_status: &'static str,
    source: &'a str,
}

#[derive(Serialize)]
struct ExportedSessionGroup<'a> {
    name: String,
    source: String,
    sessions: Vec<ExportedSession<'a>>,
}

fn export_json(sessions: &[Session]) -> String {
    let output = session_groups(sessions)
        .iter()
        .map(|group| ExportedSessionGroup {
            name: group.export_name().to_owned(),
            source: group.source.clone(),
            sessions: group
                .session_indices
                .iter()
                .map(|&index| export_json_session(&sessions[index]))
                .collect(),
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&output).unwrap_or_default()
}

fn export_json_session(session: &Session) -> ExportedSession<'_> {
    ExportedSession {
        name: &session.name,
        folder: &session.folder,
        host: &session.host,
        port: session.port,
        username: &session.username,
        password: (session.password_status == crate::core::model::PasswordStatus::Available)
            .then_some(session.password.as_str()),
        password_status: session.password_status.as_str(),
        source: &session.source,
    }
}

fn export_xml(sessions: &[Session]) -> String {
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<session_groups>");
    for group in session_groups(sessions) {
        output.push_str("\n  <source_group name=\"");
        output.push_str(&xml_escape(group.export_name()));
        output.push_str("\" source=\"");
        output.push_str(&xml_escape(&group.source));
        output.push_str("\">");
        for index in group.session_indices {
            append_xml_session(&mut output, &sessions[index], 4);
        }
        output.push_str("\n  </source_group>");
    }
    output.push_str("\n</session_groups>\n");
    output
}

fn append_xml_session(output: &mut String, session: &Session, indent: usize) {
    output.push('\n');
    output.extend(std::iter::repeat_n(' ', indent));
    output.push_str("<session>");
    append_xml_element(output, "name", &session.name, indent + 2);
    output.push('\n');
    output.extend(std::iter::repeat_n(' ', indent + 2));
    output.push_str("<folders>");
    for folder in &session.folder {
        append_xml_element(output, "folder", folder, indent + 4);
    }
    output.push('\n');
    output.extend(std::iter::repeat_n(' ', indent + 2));
    output.push_str("</folders>");
    append_xml_element(output, "host", &session.host, indent + 2);
    append_xml_element(output, "port", &session.port.to_string(), indent + 2);
    append_xml_element(output, "username", &session.username, indent + 2);
    let password = if session.password_status == crate::core::model::PasswordStatus::Available {
        session.password.as_str()
    } else {
        ""
    };
    output.push('\n');
    output.extend(std::iter::repeat_n(' ', indent + 2));
    output.push_str("<password status=\"");
    output.push_str(session.password_status.as_str());
    output.push_str("\">");
    output.push_str(&xml_escape(password));
    output.push_str("</password>");
    append_xml_element(output, "source", &session.source, indent + 2);
    output.push('\n');
    output.extend(std::iter::repeat_n(' ', indent));
    output.push_str("</session>");
}

fn session_groups(sessions: &[Session]) -> Vec<SessionGroup> {
    let indices = (0..sessions.len()).collect::<Vec<_>>();
    group_session_indices(sessions, &indices)
}

fn append_xml_element(output: &mut String, name: &str, value: &str, indent: usize) {
    output.push('\n');
    output.extend(std::iter::repeat_n(' ', indent));
    output.push('<');
    output.push_str(name);
    output.push('>');
    output.push_str(&xml_escape(value));
    output.push_str("</");
    output.push_str(name);
    output.push('>');
}

fn xml_escape(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            matches!(*character, '\u{9}' | '\u{A}' | '\u{D}')
                || ('\u{20}'..='\u{D7FF}').contains(character)
                || ('\u{E000}'..='\u{FFFD}').contains(character)
                || ('\u{10000}'..='\u{10FFFF}').contains(character)
        })
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&apos;".to_owned(),
            _ => character.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{PasswordStatus, SecretString};

    fn sample_session() -> Session {
        Session {
            name: "Production & <Blue>".to_owned(),
            host: "host.example.test".to_owned(),
            port: 2222,
            connection: crate::core::model::ConnectionKind::Sftp,
            username: "alice".to_owned(),
            folder: vec!["Team".to_owned(), "Servers".to_owned()],
            password: SecretString::new("secret<&\"'".to_owned()),
            encrypted_password: None,
            master_password_verifier: None,
            password_status: PasswordStatus::Available,
            source: "sample.ini".to_owned(),
        }
    }

    #[test]
    fn exports_text_with_the_selected_language() {
        let sessions = [sample_session()];
        let russian = export_sessions(&sessions, ExportFormat::Text, Language::Russian);
        let english = export_sessions(&sessions, ExportFormat::Text, Language::English);
        assert!(russian.starts_with("Источник: sample"));
        assert!(english.starts_with("Source: sample"));
        assert!(russian.contains("Подключение: Production & <Blue>"));
        assert!(russian.contains("Папка: Team/Servers"));
        assert!(russian.contains("Порт: 2222"));
        assert!(english.contains("Session: Production & <Blue>"));
        assert!(english.contains("Port: 2222"));
        assert!(english.contains("Password: secret<&\"'"));
    }

    #[test]
    fn exports_machine_readable_json_and_includes_passwords() {
        let output = export_sessions(&[sample_session()], ExportFormat::Json, Language::English);
        let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid json");
        assert_eq!(parsed[0]["name"], "sample");
        assert_eq!(parsed[0]["source"], "sample.ini");
        assert_eq!(parsed[0]["sessions"][0]["password"], "secret<&\"'");
        assert_eq!(parsed[0]["sessions"][0]["port"], 2222);
        assert_eq!(parsed[0]["sessions"][0]["folder"][1], "Servers");
        assert_eq!(parsed[0]["sessions"][0]["password_status"], "available");
    }

    #[test]
    fn exports_xml_with_escaped_text_and_password_status() {
        let output = export_sessions(&[sample_session()], ExportFormat::Xml, Language::Russian);
        assert!(output.contains("<source_group name=\"sample\" source=\"sample.ini\">"));
        assert!(output.contains("Production &amp; &lt;Blue&gt;"));
        assert!(output.contains("secret&lt;&amp;&quot;&apos;"));
        assert!(output.contains("<port>2222</port>"));
        assert!(output.contains("<password status=\"available\">"));
    }

    #[test]
    fn exports_sessions_in_separate_source_groups_for_all_formats() {
        let first = sample_session();
        let mut second = sample_session();
        second.name = "Backup".to_owned();
        second.source = "C:\\exports\\backup.ini".to_owned();
        let sessions = [first, second];

        let text = export_sessions(&sessions, ExportFormat::Text, Language::English);
        assert!(text.contains("Source: sample\n\nSession: Production"));
        assert!(text.contains("Source: backup\n\nSession: Backup"));

        let json = export_sessions(&sessions, ExportFormat::Json, Language::English);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed.as_array().expect("group list").len(), 2);
        assert_eq!(parsed[0]["name"], "sample");
        assert_eq!(parsed[0]["sessions"].as_array().expect("sessions").len(), 1);
        assert_eq!(parsed[1]["name"], "backup");

        let xml = export_sessions(&sessions, ExportFormat::Xml, Language::English);
        assert!(xml.contains("<source_group name=\"sample\" source=\"sample.ini\">"));
        assert!(xml.contains("<source_group name=\"backup\" source=\"C:\\exports\\backup.ini\">"));
    }

    #[test]
    fn does_not_export_unavailable_password_as_plaintext() {
        let mut session = sample_session();
        session.password = SecretString::new(String::new());
        session.password_status = PasswordStatus::MasterPasswordProtected;
        let json = export_sessions(&[session.clone()], ExportFormat::Json, Language::English);
        let xml = export_sessions(&[session], ExportFormat::Xml, Language::English);
        assert!(json.contains("master_password_protected"));
        assert!(json.contains("\"password\": null"));
        assert!(xml.contains("<password status=\"master_password_protected\"></password>"));
    }
}
