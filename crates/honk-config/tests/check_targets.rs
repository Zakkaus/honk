use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

#[test]
fn malformed_udp_dns_targets_fail_located_admission() {
    for value in [
        "[::1",
        "[::1]junk",
        "resolver.test:PRIVATE",
        "resolver.test:0",
        "resolver.test:65536",
        ":53",
        "resolver.test:",
    ] {
        let mut config = Config::default();
        config.global.udp_check_dns = vec![value.into()];
        assert!(config.validate().is_err(), "{value}");
        let mut diagnostics = Vec::new();
        let error = parse_dae_config_with_detailed_diagnostics(
            &format!("global {{\n udp_check_dns: {value}\n}}"),
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-dns-check-target");
        assert_eq!(
            error.diagnostic.setting.to_string(),
            "global.udp_check_dns[1]"
        );
        assert_eq!(error.diagnostic.line, Some(2));
        assert!(!format!("{diagnostics:?}{error:?}").contains("PRIVATE"));
    }
}
