use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use honk_config::conformance::project;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    note: String,
    case: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    input: Option<PathBuf>,
    source: Option<Source>,
    #[serde(default)]
    wrap: String,
    dae: String,
    honk: String,
    honk_diagnostics: Vec<String>,
    compare: String,
    layer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    file: PathBuf,
    lines: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn input(case: &Case) -> String {
    assert_ne!(case.input.is_some(), case.source.is_some(), "{}: one input source required", case.id);
    let mut text = if let Some(path) = &case.input {
        std::fs::read_to_string(root().join(path)).unwrap()
    } else {
        let source = case.source.as_ref().unwrap();
        let text = std::fs::read_to_string(root().join(&source.file)).unwrap();
        let (start, end) = source.lines.split_once('-').unwrap_or((&source.lines, &source.lines));
        let start: usize = start.parse().unwrap();
        let end: usize = end.parse().unwrap();
        assert!(start > 0 && end >= start && end <= text.lines().count());
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines[start - 2].trim(), "```dae", "{}: stale fence start", case.id);
        assert_eq!(lines[end].trim(), "```", "{}: stale fence end", case.id);
        format!("{}\n", lines[start - 1..end].join("\n"))
    };
    for section in case.wrap.split('.').rev().filter(|s| !s.is_empty()) {
        text = format!("{section} {{\n{text}\n}}\n");
    }
    text
}

#[test]
fn manifest_cases() {
    let manifest: Manifest = toml::from_str(&std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance/manifest.toml")
    ).unwrap()).unwrap();
    assert!(!manifest.note.is_empty());
    let list = Command::new(env!("CARGO"))
        .args(["test", "-p", "honk-config", "--lib", "--tests", "--", "--list"])
        .current_dir(root()).output().expect("list typed/loading tests");
    assert!(list.status.success(), "{}", String::from_utf8_lossy(&list.stderr));
    let listed = String::from_utf8(list.stdout).unwrap();
    let names: HashSet<_> = listed.lines().filter_map(|line| line.strip_suffix(": test"))
        .map(|name| name.rsplit("::").next().unwrap()).collect();
    let filter = std::env::var("CONFORMANCE_CASE").unwrap_or_default();
    let mut ids = HashSet::new();
    let mut count = 0;
    let mut failures = Vec::new();
    eprintln!("oracle absent: checking honk acceptance and diagnostics only");
    for case in manifest.case {
        assert!(ids.insert(case.id.clone()), "duplicate case {}", case.id);
        if !case.id.contains(&filter) { continue; }
        count += 1;
        assert!(["accept", "reject"].contains(&case.dae.as_str()));
        assert!(["accept", "reject"].contains(&case.honk.as_str()));
        assert_eq!(case.compare, "equal");
        if case.layer != "structure" {
            let (layer, test) = case.layer.split_once(':').expect("layer:test");
            assert!(["typed", "loading"].contains(&layer));
            assert!(names.contains(test), "{}: missing test {test}", case.id);
        }
        let projection = project(&input(&case));
        let codes: Vec<_> = projection.diagnostics.iter().map(|d| d.code).collect();
        if projection.accepted != (case.honk == "accept") || codes != case.honk_diagnostics {
            failures.push(format!("{}: acceptance={} diagnostics={codes:?}; expected {} {:?}", case.id, projection.accepted, case.honk, case.honk_diagnostics));
        }
    }
    assert!(count > 0, "case filter matched nothing");
    println!("conformance: {count} cases; {} failures; oracle absent", failures.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
