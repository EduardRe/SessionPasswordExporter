use clap::ValueEnum;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Text,
    Json,
    Xml,
}

impl ExportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Json => "json",
            Self::Xml => "xml",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Text => crate::config::constants::UI_FORMAT_TEXT,
            Self::Json => crate::config::constants::UI_FORMAT_JSON,
            Self::Xml => crate::config::constants::UI_FORMAT_XML,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordStatus {
    Available,
    NotStored,
    MasterPasswordProtected,
    CouldNotDecrypt,
}

impl PasswordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::NotStored => "not_stored",
            Self::MasterPasswordProtected => "master_password_protected",
            Self::CouldNotDecrypt => "could_not_decrypt",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Available => "",
            Self::NotStored => crate::config::constants::UI_PASSWORD_NOT_STORED,
            Self::MasterPasswordProtected => crate::config::constants::UI_PASSWORD_PROTECTED,
            Self::CouldNotDecrypt => crate::config::constants::UI_PASSWORD_UNAVAILABLE,
        }
    }

    pub fn localized_label(self, language: crate::config::localization::Language) -> &'static str {
        let text = crate::config::localization::labels(language);
        match self {
            Self::Available => "",
            Self::NotStored => text.password_not_stored,
            Self::MasterPasswordProtected => text.password_protected,
            Self::CouldNotDecrypt => text.password_unavailable,
        }
    }
}

#[derive(Clone, Default)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub name: String,
    pub host: String,
    pub username: String,
    pub folder: Vec<String>,
    pub password: SecretString,
    pub encrypted_password: Option<SecretString>,
    pub master_password_verifier: Option<SecretString>,
    pub password_status: PasswordStatus,
    pub source: String,
}

#[derive(Clone, Debug, Default)]
pub struct ImportReport {
    pub sessions: Vec<Session>,
    pub warnings: Vec<String>,
}

impl ImportReport {
    pub fn append(&mut self, mut other: Self) {
        self.sessions.append(&mut other.sessions);
        self.warnings.append(&mut other.warnings);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordClickAction {
    Show,
    Copy,
    #[default]
    ShowAndCopy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguagePreference {
    #[default]
    System,
    Russian,
    English,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

impl PasswordClickAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Show => crate::config::constants::UI_ACTION_SHOW,
            Self::Copy => crate::config::constants::UI_ACTION_COPY,
            Self::ShowAndCopy => crate::config::constants::UI_ACTION_SHOW_COPY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RecoverySearchSettings {
    pub minimum_length: u32,
    pub maximum_length: u32,
    pub digits: bool,
    pub letters: bool,
    pub symbols: bool,
}

impl Default for RecoverySearchSettings {
    fn default() -> Self {
        Self {
            minimum_length: crate::config::constants::RECOVERY_DEFAULT_MINIMUM_LENGTH,
            maximum_length: crate::config::constants::RECOVERY_DEFAULT_MAXIMUM_LENGTH,
            digits: true,
            letters: true,
            symbols: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub password_click_action: PasswordClickAction,
    pub language: LanguagePreference,
    pub theme: ThemePreference,
    pub exclude_collapsed_from_search: bool,
    pub recovery_search: RecoverySearchSettings,
}
