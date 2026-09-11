use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;

use tracing::warn;

/// A non-fatal configuration diagnostic, appended as encountered even if loading fails.
/// Plain entry points log diagnostics instead of returning them.
/// Node skips and legacy NFQUEUE migration still print to stderr; an empty vector
/// does not imply a warning-free load.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigDiagnostic {
    pub setting: String,
    /// Scalar diagnostics retain the parsed scalar text, including anything typed there.
    /// Filter and policy expressions are never echoed: filters use a node-filter ordinal,
    /// and policies use an empty value.
    pub value: String,
    pub message: String,
}

/// Log each diagnostic as a structured warning. The plain entry points call this
/// at parse time; the daemon calls it once its subscriber is installed.
pub fn report_diagnostics(diagnostics: &[ConfigDiagnostic]) {
    for d in diagnostics {
        warn!(setting = %d.setting, value = %d.value, "{}", d.message);
    }
}

/// Metadata only: diagnostic ownership must never keep input buffers alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticSource {
    pub path: Option<PathBuf>,
    pub parent: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DiagnosticSources(Arc<RwLock<Vec<DiagnosticSource>>>);

impl DiagnosticSources {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self(Arc::new(RwLock::new(vec![DiagnosticSource {
            path,
            parent: None,
        }])))
    }

    pub fn root(&self) -> SourceRef {
        SourceRef {
            table: self.clone(),
            index: 0,
        }
    }

    pub fn add(&self, path: Option<PathBuf>, parent: Option<usize>) -> SourceRef {
        let mut sources = self.0.write();
        let index = sources.len();
        assert!(parent.is_none_or(|parent| parent < index));
        sources.push(DiagnosticSource { path, parent });
        SourceRef {
            table: self.clone(),
            index,
        }
    }

    pub fn metadata(&self) -> Vec<DiagnosticSource> {
        self.0.read().clone()
    }
}

/// A local index is meaningful only together with its owning attempt's table.
#[derive(Debug, Clone)]
pub struct SourceRef {
    table: DiagnosticSources,
    index: usize,
}

impl SourceRef {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn sources(&self) -> &DiagnosticSources {
        &self.table
    }
    pub fn same_table(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.table.0, &other.table.0)
    }
    pub fn same_source(&self, other: &Self) -> bool {
        self.index == other.index && self.same_table(other)
    }
}

impl PartialEq for SourceRef {
    fn eq(&self, other: &Self) -> bool {
        self.same_source(other)
    }
}
impl Eq for SourceRef {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingSegment {
    Field(&'static str),
    Index(usize),
}

/// Schema names and original one-based ordinals, never operator-supplied names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingPath(pub Vec<SettingSegment>);

impl SettingPath {
    pub fn new(field: &'static str) -> Self {
        Self(vec![SettingSegment::Field(field)])
    }
    pub fn field(mut self, field: &'static str) -> Self {
        self.0.push(SettingSegment::Field(field));
        self
    }
    pub fn index(mut self, index: usize) -> Self {
        self.0.push(SettingSegment::Index(index));
        self
    }
}

impl std::fmt::Display for SettingPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, segment) in self.0.iter().enumerate() {
            match segment {
                SettingSegment::Field(field) => {
                    if index != 0 {
                        f.write_str(".")?;
                    }
                    f.write_str(field)?;
                }
                SettingSegment::Index(index) => write!(f, "[{index}]")?,
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeValue {
    Redacted,
    Empty,
    Ordinal(usize),
    Fields(Vec<&'static str>),
}

impl std::fmt::Display for SafeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redacted => f.write_str("<redacted>"),
            Self::Empty => Ok(()),
            Self::Ordinal(index) => write!(f, "{index}"),
            Self::Fields(fields) => {
                for (index, field) in fields.iter().enumerate() {
                    if index != 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(field)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedDiagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub source: SourceRef,
    pub span: Option<std::ops::Range<usize>>,
    pub line: Option<usize>,
    pub byte_column: Option<usize>,
    pub setting: SettingPath,
    pub value: SafeValue,
    pub message: &'static str,
    pub entry_index: Option<usize>,
    pub related_indices: Vec<usize>,
    pub terminal: bool,
}

impl DetailedDiagnostic {
    pub fn warning(
        code: &'static str,
        source: SourceRef,
        setting: SettingPath,
        value: SafeValue,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            severity: Severity::Warning,
            source,
            span: None,
            line: None,
            byte_column: None,
            setting,
            value,
            message,
            entry_index: None,
            related_indices: Vec::new(),
            terminal: false,
        }
    }

    pub fn to_legacy(&self) -> ConfigDiagnostic {
        ConfigDiagnostic {
            setting: self.setting.to_string(),
            value: self.value.to_string(),
            message: self.message.to_owned(),
        }
    }
}

/// Called by the outer attempt owner, not by nested readers or format probes.
pub fn finish_attempt<T>(
    result: Result<T, crate::error::DetailedConfigError>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<T, crate::error::DetailedConfigError> {
    if let Err(error) = &result {
        diagnostics.push((*error.diagnostic).clone());
    }
    result
}

/// Terminal causes are rendered by the error return path, never replayed here.
pub fn report_detailed_diagnostics(diagnostics: &[DetailedDiagnostic]) {
    for d in diagnostics.iter().filter(|d| !d.terminal) {
        match d.severity {
            Severity::Info => {
                tracing::info!(code = d.code, setting = %d.setting, value = %d.value, "{}", d.message)
            }
            Severity::Warning => {
                tracing::warn!(code = d.code, setting = %d.setting, value = %d.value, "{}", d.message)
            }
            Severity::Error => {
                tracing::error!(code = d.code, setting = %d.setting, value = %d.value, "{}", d.message)
            }
        }
    }
}
