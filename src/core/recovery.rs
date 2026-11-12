use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::config::constants::{
    RECOVERY_CHECKPOINT_FILENAME, RECOVERY_MAXIMUM_LENGTH, RECOVERY_SYMBOL_CHARSET,
};
use crate::core::model::{RecoverySearchSettings, SecretString, Session};

const RECOVERY_CHECKPOINT_VERSION: u32 = 1;
const DIGITS: &str = "0123456789";
const LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryCheckpoint {
    version: u32,
    pub sources: HashMap<String, RecoverySourceState>,
}

impl Default for RecoveryCheckpoint {
    fn default() -> Self {
        Self {
            version: RECOVERY_CHECKPOINT_VERSION,
            sources: HashMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecoverySourceState {
    pub fingerprint: String,
    pub settings: RecoverySearchSettings,
    pub current_length: u32,
    pub positions: Vec<u8>,
    pub attempts: u64,
    pub elapsed_millis: u64,
    pub found_password: Option<SecretString>,
    pub exhausted: bool,
}

impl Default for RecoverySourceState {
    fn default() -> Self {
        Self {
            fingerprint: String::new(),
            settings: RecoverySearchSettings::default(),
            current_length: 1,
            positions: Vec::new(),
            attempts: 0,
            elapsed_millis: 0,
            found_password: None,
            exhausted: false,
        }
    }
}

impl RecoveryCheckpoint {
    pub fn prepare_source(
        &mut self,
        source: &str,
        fingerprint: &str,
        settings: &RecoverySearchSettings,
    ) -> &mut RecoverySourceState {
        let state = self.sources.entry(source.to_owned()).or_default();
        if state.fingerprint != fingerprint {
            *state = RecoverySourceState {
                fingerprint: fingerprint.to_owned(),
                settings: settings.clone(),
                current_length: settings.minimum_length,
                positions: vec![0; settings.minimum_length as usize],
                ..RecoverySourceState::default()
            };
        } else if state.settings != *settings {
            if state.found_password.is_some() {
                state.settings = settings.clone();
            } else {
                *state = RecoverySourceState {
                    fingerprint: fingerprint.to_owned(),
                    settings: settings.clone(),
                    current_length: settings.minimum_length,
                    positions: vec![0; settings.minimum_length as usize],
                    ..RecoverySourceState::default()
                };
            }
        }
        state
    }

    pub fn clear_source(&mut self, source: &str) {
        self.sources.remove(source);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCursor {
    charset: Vec<char>,
    minimum_length: u32,
    maximum_length: u32,
    current_length: u32,
    positions: Vec<u8>,
    exhausted: bool,
}

impl CandidateCursor {
    pub fn new(settings: &RecoverySearchSettings) -> Result<Self, &'static str> {
        let charset = character_set(settings);
        if charset.is_empty()
            || settings.minimum_length == 0
            || settings.maximum_length < settings.minimum_length
            || settings.maximum_length > RECOVERY_MAXIMUM_LENGTH
        {
            return Err("invalid recovery search settings");
        }
        let current_length = settings.minimum_length;
        Ok(Self {
            charset: charset.chars().collect(),
            minimum_length: settings.minimum_length,
            maximum_length: settings.maximum_length,
            current_length,
            positions: vec![0; current_length as usize],
            exhausted: false,
        })
    }

    pub fn resume(
        settings: &RecoverySearchSettings,
        current_length: u32,
        positions: Vec<u8>,
        exhausted: bool,
    ) -> Result<Self, &'static str> {
        let mut cursor = Self::new(settings)?;
        if exhausted {
            cursor.exhausted = true;
            return Ok(cursor);
        }
        if !(settings.minimum_length..=settings.maximum_length).contains(&current_length)
            || positions.len() != current_length as usize
            || positions
                .iter()
                .any(|&position| usize::from(position) >= cursor.charset.len())
        {
            return Err("invalid saved recovery position");
        }
        cursor.current_length = current_length;
        cursor.positions = positions;
        Ok(cursor)
    }

    pub fn current_combination(&self) -> String {
        self.positions
            .iter()
            .map(|&position| self.charset[usize::from(position)])
            .collect()
    }

    pub fn current_length(&self) -> u32 {
        self.current_length
    }

    pub fn positions(&self) -> &[u8] {
        &self.positions
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    pub fn advance(&mut self) -> bool {
        if self.exhausted {
            return false;
        }
        for position in self.positions.iter_mut().rev() {
            if usize::from(*position) + 1 < self.charset.len() {
                *position += 1;
                return true;
            }
            *position = 0;
        }

        if self.current_length >= self.maximum_length {
            self.exhausted = true;
            return false;
        }

        self.current_length += 1;
        self.positions = vec![0; self.current_length as usize];
        true
    }
}

pub fn character_set(settings: &RecoverySearchSettings) -> String {
    let mut charset = String::new();
    if settings.digits {
        charset.push_str(DIGITS);
    }
    if settings.letters {
        charset.push_str(LETTERS);
    }
    if settings.symbols {
        charset.push_str(RECOVERY_SYMBOL_CHARSET);
    }
    charset
}

pub fn source_fingerprint(source: &str, sessions: &[Session]) -> String {
    let mut hasher = Sha1::new();
    hash_part(&mut hasher, source.as_bytes());
    let mut source_sessions = sessions
        .iter()
        .filter(|session| session.source == source && session.encrypted_password.is_some())
        .collect::<Vec<_>>();
    source_sessions.sort_by(|left, right| left.name.cmp(&right.name));
    for session in source_sessions {
        hash_part(&mut hasher, session.name.as_bytes());
        hash_part(&mut hasher, session.host.as_bytes());
        hash_part(&mut hasher, session.username.as_bytes());
        if let Some(password) = &session.encrypted_password {
            hash_part(&mut hasher, password.as_str().as_bytes());
        }
        match &session.master_password_verifier {
            Some(verifier) => {
                hash_part(&mut hasher, b"verifier");
                hash_part(&mut hasher, verifier.as_str().as_bytes());
            }
            None => hash_part(&mut hasher, b"no-verifier"),
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_part(hasher: &mut Sha1, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub fn keyspace_log10(settings: &RecoverySearchSettings) -> Option<f64> {
    let charset_size = character_set(settings).chars().count();
    if charset_size == 0
        || settings.minimum_length == 0
        || settings.maximum_length < settings.minimum_length
        || settings.maximum_length > RECOVERY_MAXIMUM_LENGTH
    {
        return None;
    }
    if charset_size == 1 {
        return Some(f64::from(settings.maximum_length - settings.minimum_length + 1).log10());
    }
    let base_log = (charset_size as f64).log10();
    let max_log = f64::from(settings.maximum_length) * base_log;
    let count = f64::from(settings.maximum_length - settings.minimum_length + 1);
    let lower_tail = 10_f64.powf(-count * base_log);
    let finite_range_log = (1.0 - lower_tail).log10();
    let geometric_factor_log = (1.0 - 1.0 / charset_size as f64).log10();
    Some(max_log + finite_range_log - geometric_factor_log)
}

pub fn checkpoint_path() -> PathBuf {
    crate::config::settings::settings_path().with_file_name(RECOVERY_CHECKPOINT_FILENAME)
}

pub fn load_checkpoint(path: &std::path::Path) -> Result<RecoveryCheckpoint, String> {
    if !path.exists() {
        return Ok(RecoveryCheckpoint {
            version: RECOVERY_CHECKPOINT_VERSION,
            sources: HashMap::new(),
        });
    }
    let encrypted = fs::read(path).map_err(|_| "could not read recovery checkpoint".to_owned())?;
    let mut plaintext = unprotect(&encrypted)?;
    let parsed = serde_json::from_slice::<RecoveryCheckpoint>(&plaintext);
    plaintext.zeroize();
    let mut checkpoint = parsed.map_err(|_| "recovery checkpoint is invalid".to_owned())?;
    if checkpoint.version != RECOVERY_CHECKPOINT_VERSION {
        checkpoint.sources.clear();
        checkpoint.version = RECOVERY_CHECKPOINT_VERSION;
    }
    Ok(checkpoint)
}

pub fn save_checkpoint(
    path: &std::path::Path,
    checkpoint: &RecoveryCheckpoint,
) -> Result<(), String> {
    let mut plaintext = serde_json::to_vec(checkpoint)
        .map_err(|_| "could not encode recovery checkpoint".to_owned())?;
    let encrypted = protect(&plaintext);
    plaintext.zeroize();
    let encrypted = encrypted?;
    let parent = path
        .parent()
        .ok_or_else(|| "recovery checkpoint path is invalid".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|_| "could not create recovery checkpoint folder".to_owned())?;
    let mut temporary = path.to_path_buf();
    temporary.set_extension("tmp");
    fs::write(&temporary, encrypted)
        .map_err(|_| "could not write encrypted recovery checkpoint".to_owned())?;
    if path.exists() {
        fs::remove_file(path).map_err(|_| "could not replace recovery checkpoint".to_owned())?;
    }
    fs::rename(&temporary, path).map_err(|_| "could not install recovery checkpoint".to_owned())
}

#[cfg(windows)]
fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let length = u32::try_from(data.len()).map_err(|_| "checkpoint is too large".to_owned())?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let success = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err("Windows could not encrypt the recovery checkpoint".to_owned());
    }
    let encrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as HLOCAL);
    }
    Ok(encrypted)
}

#[cfg(not(windows))]
fn protect(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("encrypted recovery checkpoints require Windows".to_owned())
}

#[cfg(windows)]
fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let length = u32::try_from(data.len()).map_err(|_| "checkpoint is too large".to_owned())?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let success = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err("Windows could not decrypt the recovery checkpoint for this user".to_owned());
    }
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as HLOCAL);
    }
    Ok(plaintext)
}

#[cfg(not(windows))]
fn unprotect(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("encrypted recovery checkpoints require Windows".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(minimum_length: u32, maximum_length: u32) -> RecoverySearchSettings {
        RecoverySearchSettings {
            minimum_length,
            maximum_length,
            digits: true,
            letters: false,
            symbols: false,
        }
    }

    #[test]
    fn enumerates_short_combinations_before_growing_length() {
        let mut cursor = CandidateCursor::new(&settings(1, 2)).expect("valid settings");
        assert_eq!(cursor.current_combination(), "0");
        assert!(cursor.advance());
        assert_eq!(cursor.current_combination(), "1");
        for _ in 0..9 {
            assert!(cursor.advance());
        }
        assert_eq!(cursor.current_combination(), "00");
    }

    #[test]
    fn resumes_at_a_saved_candidate_position() {
        let settings = settings(1, 3);
        let cursor =
            CandidateCursor::resume(&settings, 3, vec![0, 1, 2], false).expect("saved cursor");
        assert_eq!(cursor.current_combination(), "012");
        assert_eq!(cursor.current_length(), 3);
    }

    #[test]
    fn supports_a_maximum_length_of_one_hundred_thousand() {
        let settings = settings(1, RECOVERY_MAXIMUM_LENGTH);
        let mut cursor = CandidateCursor::new(&settings).expect("valid settings");
        for _ in 0..10 {
            assert!(cursor.advance());
        }
        assert_eq!(cursor.current_length(), 2);
        let resumed = CandidateCursor::resume(
            &settings,
            RECOVERY_MAXIMUM_LENGTH,
            vec![0; RECOVERY_MAXIMUM_LENGTH as usize],
            false,
        )
        .expect("long saved cursor");
        assert_eq!(
            resumed.current_combination().len(),
            RECOVERY_MAXIMUM_LENGTH as usize
        );
    }

    #[test]
    fn validates_character_sets_and_length_range() {
        assert!(CandidateCursor::new(&RecoverySearchSettings::default()).is_ok());
        assert!(
            CandidateCursor::new(&RecoverySearchSettings {
                digits: false,
                letters: false,
                symbols: false,
                ..RecoverySearchSettings::default()
            })
            .is_err()
        );
        assert!(CandidateCursor::new(&settings(3, 2)).is_err());
        assert!(CandidateCursor::new(&settings(1, RECOVERY_MAXIMUM_LENGTH + 1)).is_err());
    }

    #[test]
    fn special_characters_are_included_only_when_enabled() {
        let mut current = settings(1, 2);
        assert!(!character_set(&current).contains('!'));
        assert!(!character_set(&current).contains(' '));
        current.symbols = true;
        assert!(character_set(&current).contains('!'));
        assert!(character_set(&current).contains(' '));
        assert!(character_set(&current).contains('\\'));
        assert!(character_set(&current).contains('"'));
    }

    #[test]
    fn keyspace_uses_the_selected_length_range() {
        let one_digit_length = keyspace_log10(&settings(1, 1)).expect("valid keyspace");
        let two_digit_lengths = keyspace_log10(&settings(1, 2)).expect("valid keyspace");
        let only_two_digits = keyspace_log10(&settings(2, 2)).expect("valid keyspace");
        assert!((one_digit_length - 1.0).abs() < 0.000_001);
        assert!((two_digit_lengths - 2.041_393).abs() < 0.000_01);
        assert!((only_two_digits - 2.0).abs() < 0.000_001);
    }

    #[test]
    fn prepares_or_resets_checkpoint_by_fingerprint_and_search_settings() {
        let mut checkpoint = RecoveryCheckpoint::default();
        let current_settings = settings(1, 2);
        let state = checkpoint.prepare_source("C:\\saved.ini", "first", &current_settings);
        state.attempts = 37;
        let resumed = checkpoint.prepare_source("C:\\saved.ini", "first", &current_settings);
        assert_eq!(resumed.attempts, 37);
        let reset = checkpoint.prepare_source("C:\\saved.ini", "changed", &current_settings);
        assert_eq!(reset.attempts, 0);
    }

    #[test]
    fn settings_changes_reset_progress_but_keep_a_recovered_password() {
        let mut checkpoint = RecoveryCheckpoint::default();
        let first_settings = settings(1, 2);
        let state = checkpoint.prepare_source("C:\\saved.ini", "same", &first_settings);
        state.attempts = 37;
        let mut changed_settings = first_settings.clone();
        changed_settings.symbols = true;
        let reset = checkpoint.prepare_source("C:\\saved.ini", "same", &changed_settings);
        assert_eq!(reset.attempts, 0);

        reset.found_password = Some(SecretString::new("recovered".to_owned()));
        let preserved = checkpoint.prepare_source("C:\\saved.ini", "same", &first_settings);
        assert_eq!(
            preserved.found_password.as_ref().map(SecretString::as_str),
            Some("recovered")
        );
    }

    #[test]
    fn computes_a_fingerprint_for_encrypted_sources() {
        use crate::core::model::{PasswordStatus, Session};

        let session = Session {
            name: "saved".to_owned(),
            host: String::new(),
            username: String::new(),
            folder: Vec::new(),
            password: SecretString::default(),
            encrypted_password: Some(SecretString::new("wrapped".to_owned())),
            master_password_verifier: None,
            password_status: PasswordStatus::MasterPasswordProtected,
            source: "saved.ini".to_owned(),
        };
        assert_eq!(
            source_fingerprint("saved.ini", std::slice::from_ref(&session)),
            source_fingerprint("saved.ini", std::slice::from_ref(&session))
        );
        assert_ne!(
            source_fingerprint("other.ini", std::slice::from_ref(&session)),
            source_fingerprint("saved.ini", std::slice::from_ref(&session))
        );
        let mut changed_verifier = session.clone();
        changed_verifier.master_password_verifier =
            Some(SecretString::new("changed-verifier".to_owned()));
        assert_ne!(
            source_fingerprint("saved.ini", std::slice::from_ref(&session)),
            source_fingerprint("saved.ini", std::slice::from_ref(&changed_verifier))
        );
    }

    #[cfg(windows)]
    #[test]
    fn checkpoint_keeps_paths_and_found_passwords_encrypted_on_disk() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "spe-recovery-checkpoint-{}-{unique}.dat",
            std::process::id()
        ));
        let mut checkpoint = RecoveryCheckpoint::default();
        let mut state = RecoverySourceState {
            fingerprint: "fingerprint-sentinel".to_owned(),
            settings: RecoverySearchSettings::default(),
            found_password: Some(SecretString::new("master-password-sentinel".to_owned())),
            ..RecoverySourceState::default()
        };
        state.positions = vec![0; state.current_length as usize];
        checkpoint
            .sources
            .insert("C:\\private\\config-sentinel.ini".to_owned(), state);

        save_checkpoint(&path, &checkpoint).expect("save encrypted checkpoint");
        let encrypted_bytes = fs::read(&path).expect("read encrypted checkpoint");
        assert!(
            !encrypted_bytes
                .windows(b"master-password-sentinel".len())
                .any(|window| window == b"master-password-sentinel")
        );
        assert!(
            !encrypted_bytes
                .windows(b"config-sentinel".len())
                .any(|window| window == b"config-sentinel")
        );

        let loaded = load_checkpoint(&path).expect("decrypt checkpoint for same Windows user");
        let recovered = loaded
            .sources
            .get("C:\\private\\config-sentinel.ini")
            .and_then(|state| state.found_password.as_ref())
            .map(SecretString::as_str);
        assert_eq!(recovered, Some("master-password-sentinel"));
        let _ = fs::remove_file(path);
    }
}
