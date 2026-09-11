use honk_config::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SafeValue, SettingPath, finish_attempt,
};
use honk_config::error::{DetailedConfigError, ErrorCategory};

#[test]
fn failure_preserves_prefix_and_has_one_safe_terminal() {
    let first = DiagnosticSources::new(None);
    let second = DiagnosticSources::new(None);
    let prefix = DetailedDiagnostic::warning(
        "invalid-scalar",
        first.root(),
        SettingPath::new("global").field("check_tolerance"),
        SafeValue::Redacted,
        "invalid duration; keeping the default",
    );
    let mut diagnostics = vec![prefix.clone()];
    let error = DetailedConfigError::new(
        ErrorCategory::Parse,
        "invalid-value",
        second.root(),
        SettingPath::new("dns").field("client_subnet"),
        "invalid value",
    );
    let result: Result<(), _> = finish_attempt(Err(error), &mut diagnostics);
    let error = result.unwrap_err();
    assert_eq!(diagnostics[0], prefix);
    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
    assert!(!diagnostics[0].source.same_source(&diagnostics[1].source));
    assert!(matches!(
        error.into_legacy(),
        honk_config::ConfigError::Parse(_)
    ));
    assert_eq!(diagnostics[0].to_legacy().value, "<redacted>");
}

#[test]
fn source_metadata_retains_include_ancestry_without_input() {
    let sources = DiagnosticSources::new(Some("entry.dae".into()));
    let child = sources.add(Some("child.dae".into()), Some(0));
    let decoded = sources.add(None, Some(child.index()));
    assert_eq!(decoded.index(), 2);
    assert_eq!(sources.metadata()[2].parent, Some(1));
    assert_eq!(
        sources.metadata()[1].path.as_deref(),
        Some(std::path::Path::new("child.dae"))
    );
    assert!(sources.root().same_table(&decoded));
}

#[test]
fn legacy_error_projection_preserves_every_category_without_payload() {
    let sources = DiagnosticSources::new(None);
    let errors = [
        honk_config::ConfigError::Io(std::io::Error::other("secret")),
        honk_config::ConfigError::Parse("secret".into()),
        honk_config::ConfigError::Include("secret".into()),
        honk_config::ConfigError::Validation("secret".into()),
        honk_config::ConfigError::Serialization("secret".into()),
        honk_config::ConfigError::UnknownProtocol("secret".into()),
        honk_config::ConfigError::UnsupportedPolicy("secret".into()),
    ];
    for original in errors {
        let category = ErrorCategory::of(&original);
        let detailed = DetailedConfigError::from_legacy(original, sources.root());
        assert!(!format!("{detailed:?} {detailed}").contains("secret"));
        let legacy = detailed.into_legacy();
        assert_eq!(ErrorCategory::of(&legacy), category);
        assert!(!format!("{legacy:?} {legacy}").contains("secret"));
    }
}
