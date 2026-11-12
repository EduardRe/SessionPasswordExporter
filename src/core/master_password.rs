use std::collections::BTreeMap;

use crate::core::crypto::decrypt_master_password;
use crate::core::model::{PasswordStatus, SecretString, Session};

pub fn protected_sources(sessions: &[Session]) -> Vec<String> {
    let mut sources = BTreeMap::<String, ()>::new();
    for session in sessions {
        if session.encrypted_password.is_some() {
            sources.insert(session.source.clone(), ());
        }
    }
    sources.into_keys().collect()
}

pub fn unlock_protected_source(
    sessions: &mut [Session],
    source: &str,
    master_password: &str,
) -> bool {
    if master_password.is_empty() {
        return false;
    }

    let indices = sessions
        .iter()
        .enumerate()
        .filter_map(|(index, session)| {
            (session.source == source && session.encrypted_password.is_some()).then_some(index)
        })
        .collect::<Vec<_>>();
    if indices.is_empty() {
        return false;
    }

    let mut decrypted = Vec::with_capacity(indices.len());
    for &index in &indices {
        let session = &sessions[index];
        let encrypted = session
            .encrypted_password
            .as_ref()
            .expect("indices only contain protected sessions");
        match decrypt_master_password(encrypted.as_str(), master_password) {
            Ok(password) => decrypted.push((index, password)),
            Err(_) => {
                for (_, password) in &mut decrypted {
                    zeroize::Zeroize::zeroize(password);
                }
                mark_decryption_failed(sessions, &indices);
                return false;
            }
        }
    }

    for (index, password) in decrypted {
        let session = &mut sessions[index];
        session.password = SecretString::new(password);
        session.encrypted_password = None;
        session.password_status = PasswordStatus::Available;
    }
    true
}

fn mark_decryption_failed(sessions: &mut [Session], indices: &[usize]) {
    for &index in indices {
        sessions[index].password_status = PasswordStatus::CouldNotDecrypt;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::tests_support::encrypt_test_master_password;

    fn protected_session(
        name: &str,
        source: &str,
        master_password: &str,
        password: &str,
    ) -> Session {
        Session {
            name: name.to_owned(),
            host: "host.example.test".to_owned(),
            username: "admin".to_owned(),
            folder: Vec::new(),
            password: SecretString::default(),
            encrypted_password: Some(SecretString::new(encrypt_test_master_password(
                password,
                master_password,
            ))),
            master_password_verifier: None,
            password_status: PasswordStatus::MasterPasswordProtected,
            source: source.to_owned(),
        }
    }

    #[test]
    fn decrypts_all_sessions_for_a_matching_source_and_keeps_other_sources_locked() {
        let mut sessions = vec![
            protected_session("One", "one.ini", "first", "secret one"),
            protected_session("Two", "one.ini", "first", "secret two"),
            protected_session("Three", "two.ini", "second", "secret three"),
        ];

        assert!(unlock_protected_source(&mut sessions, "one.ini", "first"));
        assert_eq!(sessions[0].password.as_str(), "secret one");
        assert_eq!(sessions[1].password.as_str(), "secret two");
        assert!(sessions[0].encrypted_password.is_none());
        assert!(sessions[2].encrypted_password.is_some());
        assert!(!unlock_protected_source(&mut sessions, "two.ini", "first"));
        assert_eq!(sessions[2].password_status, PasswordStatus::CouldNotDecrypt);
        assert!(sessions[2].encrypted_password.is_some());
    }

    #[test]
    fn reports_unique_sources_that_still_have_locked_passwords() {
        let sessions = vec![
            protected_session("One", "one.ini", "first", "secret one"),
            protected_session("Two", "one.ini", "first", "secret two"),
            protected_session("Three", "two.ini", "second", "secret three"),
        ];
        assert_eq!(protected_sources(&sessions), ["one.ini", "two.ini"]);
    }

    #[test]
    fn decrypts_session_passwords_when_a_verifier_is_present() {
        let mut session = protected_session("One", "one.ini", "correct", "secret");
        session.master_password_verifier = Some(SecretString::new(
            crate::core::crypto::tests_support::create_test_verifier("different"),
        ));
        let mut sessions = vec![session];

        assert!(!unlock_protected_source(
            &mut sessions,
            "one.ini",
            "incorrect"
        ));
        assert_eq!(sessions[0].password_status, PasswordStatus::CouldNotDecrypt);
        assert!(sessions[0].encrypted_password.is_some());
        assert!(unlock_protected_source(&mut sessions, "one.ini", "correct"));
        assert_eq!(sessions[0].password.as_str(), "secret");
    }

    #[test]
    fn verifier_does_not_veto_a_password_that_authenticates_all_payloads() {
        let mut session = protected_session("One", "one.ini", "correct", "secret");
        session.master_password_verifier = Some(SecretString::new(
            crate::core::crypto::tests_support::create_test_verifier("different"),
        ));
        let mut sessions = vec![session];

        assert!(unlock_protected_source(&mut sessions, "one.ini", "correct"));
        assert_eq!(sessions[0].password.as_str(), "secret");
    }

    #[test]
    fn does_not_partially_unlock_a_source_when_one_password_fails() {
        let mut sessions = vec![
            protected_session("One", "one.ini", "correct", "secret one"),
            protected_session("Two", "one.ini", "different", "secret two"),
        ];

        assert!(!unlock_protected_source(
            &mut sessions,
            "one.ini",
            "correct"
        ));

        assert!(sessions.iter().all(|session| session.password.is_empty()));
        assert!(
            sessions
                .iter()
                .all(|session| session.encrypted_password.is_some())
        );
        assert!(
            sessions
                .iter()
                .all(|session| session.password_status == PasswordStatus::CouldNotDecrypt)
        );
    }
}
