use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Include error: {0}")]
    Include(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Unknown node protocol: {0}")]
    UnknownProtocol(String),

    #[error("Unsupported policy: {0}")]
    UnsupportedPolicy(String),
}

/// The legacy exhaustive matching surface, without an input-bearing payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Io(std::io::ErrorKind),
    Parse,
    Include,
    Validation,
    Serialization,
    UnknownProtocol,
    UnsupportedPolicy,
}

impl ErrorCategory {
    pub fn of(error: &ConfigError) -> Self {
        match error {
            ConfigError::Io(error) => Self::Io(error.kind()),
            ConfigError::Parse(_) => Self::Parse,
            ConfigError::Include(_) => Self::Include,
            ConfigError::Validation(_) => Self::Validation,
            ConfigError::Serialization(_) => Self::Serialization,
            ConfigError::UnknownProtocol(_) => Self::UnknownProtocol,
            ConfigError::UnsupportedPolicy(_) => Self::UnsupportedPolicy,
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("{setting}: {message}", setting = .diagnostic.setting, message = .diagnostic.message)]
pub struct DetailedConfigError {
    pub category: ErrorCategory,
    pub diagnostic: Box<crate::diagnostic::DetailedDiagnostic>,
}

impl DetailedConfigError {
    pub fn new(
        category: ErrorCategory,
        code: &'static str,
        source: crate::diagnostic::SourceRef,
        setting: crate::diagnostic::SettingPath,
        message: &'static str,
    ) -> Self {
        let mut diagnostic = crate::diagnostic::DetailedDiagnostic::warning(
            code,
            source,
            setting,
            crate::diagnostic::SafeValue::Redacted,
            message,
        );
        diagnostic.severity = crate::diagnostic::Severity::Error;
        diagnostic.terminal = true;
        Self {
            category,
            diagnostic: Box::new(diagnostic),
        }
    }

    /// Unknown legacy prose is deliberately withheld, including serde/IO sources.
    pub fn from_legacy(error: ConfigError, source: crate::diagnostic::SourceRef) -> Self {
        use crate::diagnostic::SettingPath;
        let category = ErrorCategory::of(&error);
        let (code, message) = match category {
            ErrorCategory::Io(_) => ("config-io", "configuration IO failed"),
            ErrorCategory::Parse => ("config-parse", "invalid configuration"),
            ErrorCategory::Include => ("config-include", "invalid configuration include"),
            ErrorCategory::Validation => ("config-validation", "configuration validation failed"),
            ErrorCategory::Serialization => {
                ("config-serialization", "configuration serialization failed")
            }
            ErrorCategory::UnknownProtocol => ("unknown-protocol", "unknown node protocol"),
            ErrorCategory::UnsupportedPolicy => ("unsupported-policy", "unsupported group policy"),
        };
        Self::new(category, code, source, SettingPath::new("config"), message)
    }

    pub fn into_legacy(self) -> ConfigError {
        let message = self.to_string();
        match self.category {
            ErrorCategory::Io(kind) => ConfigError::Io(std::io::Error::new(kind, message)),
            ErrorCategory::Parse => ConfigError::Parse(message),
            ErrorCategory::Include => ConfigError::Include(message),
            ErrorCategory::Validation => ConfigError::Validation(message),
            ErrorCategory::Serialization => ConfigError::Serialization(message),
            ErrorCategory::UnknownProtocol => ConfigError::UnknownProtocol(message),
            ErrorCategory::UnsupportedPolicy => ConfigError::UnsupportedPolicy(message),
        }
    }
}
