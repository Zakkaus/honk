use std::path::PathBuf;
use std::sync::Arc;

use honk_config::parser::{LoadedConfig, SourceLimits, parse_dae_sources};

const NODE: &str = "socks5://127.0.0.1:1080";

fn load(documents: &[&str]) -> LoadedConfig {
    let inputs: Vec<_> = documents
        .iter()
        .enumerate()
        .map(|(index, content)| {
            (
                PathBuf::from(format!("/etc/honk/{index}.dae")),
                Arc::<str>::from(*content),
            )
        })
        .collect();
    parse_dae_sources(&inputs, SourceLimits::DEFAULT, &mut Vec::new()).unwrap()
}

/// The refusal names `setting` and points at `written`, the first occurrence
/// of that text in document `document`.
fn assert_located(documents: &[&str], setting: &str, document: usize, written: &str) {
    let loaded = load(documents);
    let error = loaded.validate_detailed().unwrap_err();
    let diagnostic = &error.diagnostic;
    assert_eq!(diagnostic.setting.to_string(), setting);
    let content = documents[document];
    let start = content.find(written).expect("written text");
    let line_start = content[..start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    assert_eq!(
        diagnostic.source.index(),
        loaded.sources[document].source.index(),
        "{setting}"
    );
    assert_eq!(
        diagnostic.line,
        Some(content[..start].matches('\n').count() + 1)
    );
    assert_eq!(diagnostic.byte_column, Some(start - line_start + 1));
    let span = diagnostic.span.clone().expect("span");
    assert_eq!(span.start, start, "{setting}");
    assert!(
        content[span].starts_with(written.trim_end()),
        "{setting} points at {written:?}"
    );
}

#[test]
fn global_refusal_points_at_its_field() {
    assert_located(
        &["global {\n  tproxy_port: 12345\n  dial_mode: sideways\n}\n"],
        "global.dial_mode",
        0,
        "dial_mode: sideways",
    );
}

#[test]
fn node_refusal_points_at_its_entry() {
    assert_located(
        &[&format!(
            "node {{\n  first: '{NODE}'\n  direct: '{NODE}'\n}}\nrouting {{\n  fallback: direct\n}}\n"
        )],
        "nodes[2]",
        0,
        "direct: '",
    );
}

#[test]
fn group_refusal_points_at_its_declaration() {
    assert_located(
        &[
            &format!("node {{\n  beta: '{NODE}'\n}}\n"),
            "group {\n  alpha {\n    policy: min\n  }\n  beta {\n    policy: min\n  }\n}\nrouting {\n  fallback: alpha\n}\n",
        ],
        "groups[2].name",
        1,
        "beta",
    );
}

#[test]
fn routing_refusals_point_at_the_rule_in_its_source() {
    let main = "global {\n  tproxy_port: 12345\n}\n";
    assert_located(
        &[
            main,
            "routing {\n  domain(a.test) -> direct\n  domain(b.test) -> missing\n  fallback: direct\n}\n",
        ],
        "routing.rules[2].outbound",
        1,
        "domain(b.test) -> missing",
    );
    assert_located(
        &[
            main,
            "routing {\n  domain(a.test) -> direct\n  fallback: missing\n}\n",
        ],
        "routing.fallback",
        1,
        "fallback: missing",
    );
}

#[test]
fn subscription_refusal_points_at_its_entry() {
    assert_located(
        &[
            "subscription {\n  sub: 'https://example.test/sub'\n  other: 'https://example.test/other' { route: missing }\n}\n",
        ],
        "subscriptions[2].download_detour",
        0,
        "other: '",
    );
}

#[test]
fn unwritten_setting_keeps_no_location() {
    let loaded = load(&["global {\n  tproxy_port: 12345\n}\n"]);
    let mut diagnostic = honk_config::error::DetailedConfigError::new(
        honk_config::error::ErrorCategory::Validation,
        "invalid-config-value",
        loaded.sources[0].source.clone(),
        honk_config::diagnostic::SettingPath::new("dns").field("bind"),
        "test",
    )
    .diagnostic;
    loaded.locate(&mut diagnostic);
    assert_eq!(diagnostic.span, None);
    assert_eq!(diagnostic.line, None);
}

#[test]
fn dns_refusal_points_at_its_rule() {
    assert_located(
        &[
            "dns {\n  upstream {\n    google: 'udp://8.8.8.8:53'\n  }\n  routing {\n    request {\n      qname(a.test) -> google\n      fallback: missing\n    }\n  }\n}\n",
        ],
        "dns.routing.request.fallback",
        0,
        "fallback: missing",
    );
}
