use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

fn input(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/pr2/c08/{name}.dae",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn dns_hosts_keep_glued_hash_data_and_source_order() {
    let source = input("k01-ordered-hosts");
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap();
    assert_eq!(
        config.dns.hosts,
        ["/etc/hosts", "/tmp/a#b", "agent # build", "/tmp/don't"]
    );
    let warnings: Vec<_> = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "legacy-glued-hash")
        .collect();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].line, Some(3));
    assert_eq!(
        warnings[0].span.as_ref().unwrap().start,
        source.find('#').unwrap()
    );
}

#[test]
fn dns_scalar_unterminated_quote_is_a_terminal_lexical_error() {
    let source = input("k05-scalar-quote");
    let mut diagnostics = Vec::new();
    let error = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap_err();
    assert_eq!(error.diagnostic.code, "unterminated-quote");
    assert_eq!(error.diagnostic.line, Some(2));
    assert!(error.diagnostic.span.is_some());
    assert_eq!(
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "unterminated-quote")
            .count(),
        1
    );
}

#[test]
fn dns_scalar_quotes_remove_only_the_enclosing_pair() {
    let source = input("k14-scalar-quote-pair");
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap();
    assert_eq!(config.dns.hosts, ["\"hosts\""]);
}

#[test]
fn bare_apostrophes_cannot_pair_across_a_comment_or_hide_the_closer() {
    let source = input("k05-bare-apostrophe-before-comment");
    let config = parse_dae_config_with_detailed_diagnostics(&source, &mut Vec::new()).unwrap();
    assert_eq!(config.dns.hosts, ["/tmp/don't"]);
}
