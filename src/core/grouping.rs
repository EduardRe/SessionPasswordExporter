use std::collections::HashMap;

use crate::config::constants::{
    REGISTRY_SOURCE_PREFIX, SOURCE_GROUP_REGISTRY_NAME, SOURCE_GROUP_UNKNOWN_NAME,
};
use crate::config::localization::{Language, labels};
use crate::core::model::Session;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionGroupKind {
    File,
    Registry,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGroup {
    pub source: String,
    pub name: String,
    pub kind: SessionGroupKind,
    pub session_indices: Vec<usize>,
}

impl SessionGroup {
    pub fn localized_name(&self, language: Language) -> String {
        let text = labels(language);
        match self.kind {
            SessionGroupKind::File => self.name.clone(),
            SessionGroupKind::Registry => text.source_group_registry.to_owned(),
            SessionGroupKind::Unknown => text.source_group_unknown.to_owned(),
        }
    }

    pub fn export_name(&self) -> &str {
        match self.kind {
            SessionGroupKind::File => &self.name,
            SessionGroupKind::Registry => SOURCE_GROUP_REGISTRY_NAME,
            SessionGroupKind::Unknown => SOURCE_GROUP_UNKNOWN_NAME,
        }
    }
}

pub fn group_session_indices(sessions: &[Session], indices: &[usize]) -> Vec<SessionGroup> {
    let mut groups = Vec::<SessionGroup>::new();
    let mut group_indices = HashMap::<String, usize>::new();

    for &session_index in indices {
        let Some(session) = sessions.get(session_index) else {
            continue;
        };

        let source = session.source.clone();
        let group_index = *group_indices.entry(source.clone()).or_insert_with(|| {
            let (kind, name) = source_group_identity(&source);
            let index = groups.len();
            groups.push(SessionGroup {
                source: source.clone(),
                name,
                kind,
                session_indices: Vec::new(),
            });
            index
        });
        groups[group_index].session_indices.push(session_index);
    }

    groups
}

fn source_group_identity(source: &str) -> (SessionGroupKind, String) {
    if source
        .get(..REGISTRY_SOURCE_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(REGISTRY_SOURCE_PREFIX))
    {
        return (SessionGroupKind::Registry, String::new());
    }

    let Some(file_name) = source
        .rsplit(['/', '\\'])
        .next()
        .filter(|file_name| !file_name.is_empty())
    else {
        return (SessionGroupKind::Unknown, String::new());
    };

    let name = file_name
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(file_name, |(stem, _)| stem);
    (SessionGroupKind::File, name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{PasswordStatus, SecretString};

    fn sample(source: &str) -> Session {
        Session {
            name: "session".to_owned(),
            host: String::new(),
            port: 22,
            connection: crate::core::model::ConnectionKind::Sftp,
            username: String::new(),
            folder: Vec::new(),
            password: SecretString::default(),
            encrypted_password: None,
            master_password_verifier: None,
            password_status: PasswordStatus::NotStored,
            source: source.to_owned(),
        }
    }

    #[test]
    fn groups_sessions_by_source_and_uses_filename_without_extension() {
        let sessions = [
            sample("C:\\configs\\production.ini"),
            sample("C:\\configs\\production.ini"),
            sample("C:\\configs\\staging.conf.ini"),
        ];
        let groups = group_session_indices(&sessions, &[0, 1, 2]);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "production");
        assert_eq!(groups[0].session_indices, [0, 1]);
        assert_eq!(groups[1].name, "staging.conf");
    }

    #[test]
    fn keeps_same_named_files_from_different_directories_separate() {
        let sessions = [sample("C:\\one\\config.ini"), sample("C:\\two\\config.ini")];
        let groups = group_session_indices(&sessions, &[0, 1]);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, groups[1].name);
        assert_ne!(groups[0].source, groups[1].source);
    }

    #[test]
    fn gives_registry_sources_a_localized_group_name() {
        let sessions = [sample("HKCU\\Software\\WinSCP\\Sessions")];
        let groups = group_session_indices(&sessions, &[0]);

        assert_eq!(groups[0].kind, SessionGroupKind::Registry);
        assert_eq!(groups[0].localized_name(Language::Russian), "Реестр WinSCP");
        assert_eq!(groups[0].export_name(), "WinSCP Registry");
    }
}
