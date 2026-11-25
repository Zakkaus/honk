//! Production code takes its data directory from the engine's `DataRoot`. The
//! process-wide directory (`honk_config::paths::data_dir`) and the daemon's
//! legacy and system search order serve only the sites allowed below; a new
//! reader fails this test, because under an explicit root it would silently
//! use `/var/lib/honk` or a system directory instead.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Names that read the process data root or the daemon search order, and the
/// process-default wrappers built on them.
const READERS: &[&str] = &[
    "paths::data_dir",
    "paths::{",
    "resolve_artifact_path",
    "resolve_dependency_path",
    "DataRoot::process",
    "LEGACY_DATA_DIR",
    "DAE_LOCATION_ASSET",
    "find_dat(",
    "find_geosite_dat",
    "find_geoip_dat",
    "GeoSourceSet::load(",
    "probe_union(",
    "HostsSourceSet::load(",
    "probe_fingerprint(",
    "resolved_log_file_path(",
    "Router::new(&",
    "Router::from_config(",
    "DnsRouter::new(",
    "new_with_fixed_ttl(",
    "new_from_dns_config(",
    "with_policy_from_config(",
    "with_hosts_from_config(",
    "build_forwarder_from_config(",
    "DnsResolver::new(",
    "DnsResolver::with_forwarder(",
    "ControlPlane::new(",
    "new_with_upstream_pool(",
];

/// The implementation of the search order itself.
const EXCLUDED: &[&str] = &["crates/honk-config/src/paths.rs"];

const RELOAD_05B: &str = "CONTRIBUTING §2: reload threading is PR 05b, originated by a human";
const ECH_05C: &str = "ECH config path threading through honk-outbound is follow-up 05c";
const WRAPPER: &str = "process-default wrapper for tests, benches and honk-tool; the engine \
                       path in lib.rs loads from its own DataRoot";
const NO_FILE: &str = "empty requirements read no file";

/// `(file, text, reason)`: every hit in `file` whose line contains `text`.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/honk-core/src/control/reload/transaction.rs",
        "GeoSourceSet::probe_union(traffic_geo, dns_geo)",
        RELOAD_05B,
    ),
    (
        "crates/honk-core/src/control/reload/transaction.rs",
        "HostsSourceSet::probe_fingerprint(&new_config.dns)",
        RELOAD_05B,
    ),
    (
        "crates/honk-core/src/control/reload/transaction.rs",
        "GeoSourceSet::load(&traffic_geo.union(&dns_geo))",
        RELOAD_05B,
    ),
    (
        "crates/honk-core/src/control/reload/transaction.rs",
        "GeoSourceSet::load(&geo_requirements)",
        RELOAD_05B,
    ),
    (
        "crates/honk-core/src/control/reload/dns.rs",
        "HostsSourceSet::load(&config.dns)",
        RELOAD_05B,
    ),
    (
        "crates/honk-core/src/control/reload/policy.rs",
        "resolved_log_file_path(candidate, log_files.cli_override",
        RELOAD_05B,
    ),
    (
        "crates/honk-outbound/src/tls.rs",
        "resolve_dependency_path(path)",
        ECH_05C,
    ),
    (
        "crates/honk-core/src/lib.rs",
        "honk_config::paths::data_dir().display()",
        "names the installed root in the refusal",
    ),
    (
        "crates/honk-core/src/logging.rs",
        "DataRoot::process()",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/routing/geo.rs",
        "DataRoot::process()",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/routing/geo.rs",
        "find_dat(\"geo",
        "honk-tool's default search, documented in its CLI reference",
    ),
    (
        "crates/honk-core/src/routing/mod.rs",
        "GeoSourceSet::load(&requirements)",
        NO_FILE,
    ),
    (
        "crates/honk-core/src/routing/mod.rs",
        "GeoSourceSet::load(&GeoRequirements::for_traffic(",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/native_api/offline/admission.rs",
        "GeoSourceSet::load(&GeoRequirements::default())",
        NO_FILE,
    ),
    (
        "crates/honk-core/src/dns/forwarder/hosts.rs",
        "DataRoot::process()",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/forwarder.rs",
        "DataRoot::process()",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/routing.rs",
        "DataRoot::process()",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/routing/mod.rs",
        "DataRoot::process()",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/routing.rs",
        "GeoSourceSet::load(&requirements)",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/routing.rs",
        "Self::new_with_fixed_ttl(",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/resolver.rs",
        "GeoSourceSet::load(&requirements)",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/resolver.rs",
        "with_policy_from_config(config)",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/resolver.rs",
        "build_forwarder_from_config(config)",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/dns/bench_support.rs",
        "benchmark",
        "dns-bench fixture",
    ),
    (
        "crates/honk-core/src/control/bootstrap.rs",
        "DataRoot::process()",
        WRAPPER,
    ),
    (
        "crates/honk-core/src/subscription/store.rs",
        "LEGACY_DATA_DIR",
        "daemon-only branch; an explicit root returns before it",
    ),
    (
        "crates/honk-tool/src/sub/udp.rs",
        "DnsResolver::new(",
        "honk-tool runs no engine",
    ),
    (
        "crates/honk-core/src/routing/mod.rs",
        "find_geoip_dat, find_geosite_dat",
        "re-export for honk-tool's default search",
    ),
    (
        "crates/honk-tool/src/geo.rs",
        "find_geo",
        "honk-tool runs no engine; its default search is documented in its CLI reference",
    ),
    (
        "crates/honk-tool/src/geo.rs",
        "DAE_LOCATION_ASSET",
        "error text naming the default search",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Hit {
    file: String,
    line: usize,
    text: String,
}

#[derive(Default)]
struct Scan {
    files: usize,
    hits: Vec<Hit>,
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Scans `crates/*/src` below `root`, skipping test-only modules and items.
fn scan(root: &Path) -> Scan {
    let mut sources = Vec::new();
    if let Ok(crates) = std::fs::read_dir(root.join("crates")) {
        for entry in crates.flatten() {
            collect(&entry.path().join("src"), &mut sources);
        }
    }
    sources.sort();
    let test_modules = test_modules(&sources);
    let mut scan = Scan::default();
    for file in &sources {
        let relative = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if EXCLUDED.contains(&relative.as_str())
            || test_modules.iter().any(|module| file.starts_with(module))
        {
            continue;
        }
        scan.files += 1;
        let text = std::fs::read_to_string(file).unwrap();
        for (line, content) in production_lines(&text) {
            let code = content.trim();
            if code.starts_with("//") {
                continue;
            }
            if READERS.iter().any(|reader| reads(code, reader)) {
                scan.hits.push(Hit {
                    file: relative.clone(),
                    line,
                    text: code.to_owned(),
                });
            }
        }
    }
    scan
}

/// A use of `reader` on `code`, not the definition of a function by that name.
fn reads(code: &str, reader: &str) -> bool {
    code.match_indices(reader)
        .any(|(at, _)| !code[..at].ends_with("fn "))
}

fn collect(directory: &Path, sources: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

/// `#[cfg(test)]` or `#[cfg(all(test, ..))]`: code compiled only for tests.
/// `any(.., test)` also builds production code, so it is scanned.
fn is_test_cfg(line: &str) -> bool {
    let Some(predicate) = line
        .trim()
        .strip_prefix("#[cfg(")
        .and_then(|rest| rest.strip_suffix(")]"))
    else {
        return false;
    };
    predicate == "test"
        || predicate
            .strip_prefix("all(")
            .and_then(|rest| rest.strip_suffix(')'))
            .is_some_and(|terms| terms.split(", ").any(|term| term == "test"))
}

/// Files and directories of modules declared as `#[cfg(test)] mod name;`.
fn test_modules(sources: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut modules = BTreeSet::new();
    for file in sources {
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !is_test_cfg(line) {
                continue;
            }
            let attributes: Vec<&str> = lines[index + 1..]
                .iter()
                .map(|line| line.trim())
                .take_while(|line| line.starts_with("#["))
                .collect();
            let Some(item) = lines
                .get(index + 1 + attributes.len())
                .map(|line| line.trim())
            else {
                continue;
            };
            let Some(name) = item
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub(super) ")
                .trim_start_matches("pub ")
                .strip_prefix("mod ")
                .and_then(|rest| rest.strip_suffix(';'))
            else {
                continue;
            };
            let parent = file.parent().unwrap();
            if let Some(path) = attributes.iter().find_map(|attribute| {
                attribute
                    .strip_prefix("#[path = \"")
                    .and_then(|rest| rest.strip_suffix("\"]"))
            }) {
                let path = parent.join(path);
                modules.insert(path.with_extension(""));
                modules.insert(path);
                continue;
            }
            let stem = file.file_stem().unwrap();
            let base = if ["mod", "lib", "main"].iter().any(|own| stem == *own) {
                parent.to_path_buf()
            } else {
                parent.join(stem)
            };
            modules.insert(base.join(format!("{name}.rs")));
            modules.insert(base.join(name));
        }
    }
    modules
}

/// Numbered lines outside items gated on `test`. An item ends on its first
/// line, or on the first later line at its indentation that closes it; the
/// tree is rustfmt-formatted, which CI enforces.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let indent = |line: &str| line.len() - line.trim_start().len();
    let mut kept = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !is_test_cfg(lines[index]) {
            kept.push((index + 1, lines[index]));
            index += 1;
            continue;
        }
        index += 1;
        while index < lines.len() && lines[index].trim().starts_with("#[") {
            index += 1;
        }
        let Some(start) = lines.get(index) else {
            break;
        };
        let depth = indent(start);
        let single = start.trim_end().ends_with(';') || start.trim_end().ends_with("{}");
        index += 1;
        if single {
            continue;
        }
        while index < lines.len() {
            let line = lines[index];
            index += 1;
            let code = line.trim();
            if indent(line) == depth
                && (code.starts_with('}') || code.starts_with([')', ']']) && code.ends_with(';'))
            {
                break;
            }
        }
    }
    kept
}

fn allowed(hit: &Hit) -> Option<usize> {
    ALLOWED
        .iter()
        .position(|(file, text, _)| *file == hit.file && hit.text.contains(text))
}

#[test]
fn production_code_reads_no_process_data_root() {
    let scan = scan(&workspace());
    assert!(
        scan.files > 300,
        "scanned only {} source files; the scan root or the test-module filter is wrong",
        scan.files
    );
    let unexpected: Vec<_> = scan
        .hits
        .iter()
        .filter(|hit| allowed(hit).is_none())
        .map(|hit| format!("{}:{}: {}", hit.file, hit.line, hit.text))
        .collect();
    assert!(
        unexpected.is_empty(),
        "these sites read the process data root or the daemon search order; take the \
         engine's DataRoot instead, or add an entry with its reason to ALLOWED:\n{}",
        unexpected.join("\n")
    );
    let used: BTreeSet<_> = scan.hits.iter().filter_map(allowed).collect();
    let stale: Vec<_> = ALLOWED
        .iter()
        .enumerate()
        .filter(|(index, _)| !used.contains(index))
        .map(|(_, (file, text, reason))| format!("{file}: {text:?} ({reason})"))
        .collect();
    assert!(
        stale.is_empty(),
        "these ALLOWED entries match nothing; remove them or update their text:\n{}",
        stale.join("\n")
    );
}

#[test]
fn the_scan_finds_a_planted_reader_and_skips_test_code() {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("crates/planted/src");
    std::fs::create_dir_all(src.join("checks")).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        "mod checks;\n\
         pub fn engine() -> &'static std::path::Path {\n    honk_config::paths::data_dir()\n}\n\
         #[cfg(not(test))]\nfn kept() { let _ = DataRoot::process(); }\n\
         #[cfg(test)]\nmod tests {\n    fn skipped() {\n        honk_config::paths::data_dir();\n    }\n}\n\
         #[cfg(test)]\nfn skipped_too() { let _ = DataRoot::process(); }\n\
         #[cfg(test)]\npub fn long(\n    a: u8,\n) -> u8 {\n    paths::data_dir();\n    a\n}\n\
         pub fn new_with_upstream_pool(\n) {}\n\
         fn after() { paths::data_dir(); }\n\
         #[cfg(any(feature = \"x\", test))]\nfn shared() { paths::data_dir(); }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("checks.rs"),
        "#[cfg(test)]\nmod tests;\n#[cfg(all(test, feature = \"x\"))]\nmod more;\n\
         #[cfg(test)]\n#[path = \"elsewhere_tests.rs\"]\nmod elsewhere;\n",
    )
    .unwrap();
    std::fs::create_dir_all(src.join("checks/more")).unwrap();
    std::fs::write(
        src.join("checks/tests.rs"),
        "fn a() { paths::data_dir(); }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("checks/more/deep.rs"),
        "fn b() { paths::data_dir(); }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("elsewhere_tests.rs"),
        "fn c() { paths::data_dir(); }\n",
    )
    .unwrap();

    let planted = scan(root.path());
    let found: Vec<_> = planted
        .hits
        .iter()
        .map(|hit| (hit.file.as_str(), hit.line))
        .collect();
    assert_eq!(
        found,
        [
            ("crates/planted/src/lib.rs", 3),
            ("crates/planted/src/lib.rs", 6),
            ("crates/planted/src/lib.rs", 24),
            ("crates/planted/src/lib.rs", 26)
        ]
    );
    assert_eq!(planted.files, 2, "test-only module files are not scanned");

    let empty = tempfile::tempdir().unwrap();
    assert_eq!(scan(empty.path()).files, 0);
}

struct NoDns;

#[async_trait::async_trait]
impl honk_core::dns::forwarder::DnsUpstreamPool for NoDns {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        panic!("building an engine must not issue DNS queries")
    }
}

#[tokio::test]
async fn an_embedder_hands_the_control_plane_its_own_root() {
    use std::sync::Arc;

    use honk_config::paths::DataRoot;
    use honk_core::dns::forwarder::DnsForwarder;

    let directory = tempfile::tempdir().unwrap();
    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    let router =
        honk_core::routing::Router::new(&config.routing.rules, &config.routing.default_outbound)
            .unwrap();
    let forwarder = Arc::new(DnsForwarder::new(
        Arc::new(NoDns),
        Arc::new(tokio::sync::Mutex::new(
            honk_core::dns::cache::DnsCache::new(16),
        )),
        Arc::new(honk_core::dns::routing::DnsRouter::new_from_dns_config(&config.dns).unwrap()),
    ));
    let plane = honk_core::control::ControlPlane::new_with_data_root(
        config.clone(),
        Box::new(honk_core::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(honk_core::proxy::ProxyRegistry::default_resolver().unwrap()),
        honk_core::dns::DnsResolver::new(&config.dns).unwrap(),
        forwarder,
        DataRoot::explicit(directory.path()),
    )
    .unwrap();

    assert_eq!(plane.data_root(), &DataRoot::explicit(directory.path()));
    assert_eq!(plane.data_root().dir(), directory.path());
}

#[test]
fn an_embedder_loads_geodata_and_hosts_from_its_own_root() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use honk_config::paths::DataRoot;
    use honk_core::dns::forwarder::DnsForwarder;
    use honk_core::dns::routing::DnsRouter;
    use honk_core::routing::{ConnectionInfo, Router};

    let geosite = workspace().join("geosite.dat");
    assert!(
        geosite.is_file(),
        "{} is required; copy the pinned geodata into the workspace",
        geosite.display()
    );
    // `geo_dir` holds the geosite asset; `plain_dir` holds none, while the
    // workspace and the daemon search order around it still do.
    let geo_dir = tempfile::tempdir().unwrap();
    let plain_dir = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    std::fs::copy(&geosite, geo_dir.path().join("geosite.dat")).unwrap();
    std::fs::write(
        geo_dir.path().join("embedder.hosts"),
        "example.test 192.0.2.1\n",
    )
    .unwrap();
    std::fs::write(
        plain_dir.path().join("embedder.hosts"),
        "example.test 192.0.2.2\n",
    )
    .unwrap();

    let mut config = honk_config::parser::parse_dae_config(
        "dns {\n upstream {\n u: 'udp://127.0.0.1:53'\n }\n\
         routing { request {\n qname(geosite:cn) -> u\n fallback: u\n } } }\n\
         routing {\n domain(geosite:cn) -> direct\n fallback: proxy\n }",
    )
    .unwrap();
    config.dns.hosts = vec!["embedder.hosts".to_owned()];

    let route = |root: &DataRoot| {
        let router = Router::from_config_in(&config.routing, root).unwrap();
        router
            .route(&ConnectionInfo {
                domain: Some("baidu.com".to_owned()),
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                dst_port: 443,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                src_port: 40000,
                protocol: "tcp",
                process_name: None,
                mac: None,
                dscp: None,
            })
            .to_owned()
    };
    let with_geo = DataRoot::explicit(geo_dir.path());
    let without_geo = DataRoot::explicit(plain_dir.path());
    assert_eq!(route(&with_geo), "direct");
    assert_eq!(route(&without_geo), "proxy");

    let forwarder = |geo: &DataRoot, hosts: &DataRoot| {
        DnsForwarder::new(
            Arc::new(NoDns),
            Arc::new(tokio::sync::Mutex::new(
                honk_core::dns::cache::DnsCache::new(16),
            )),
            Arc::new(DnsRouter::new_from_dns_config_in(&config.dns, geo).unwrap()),
        )
        .with_policy_from_config_in(&config.dns, hosts)
    };
    let policy = |geo: &DataRoot, hosts: &DataRoot| forwarder(geo, hosts).unwrap().policy_id();
    assert!(
        policy(&with_geo, &with_geo) == policy(&with_geo, &with_geo),
        "the same root gives the same policy"
    );
    assert!(
        policy(&with_geo, &with_geo) != policy(&without_geo, &with_geo),
        "DNS geodata comes from the root"
    );
    assert!(
        policy(&with_geo, &with_geo) != policy(&with_geo, &without_geo),
        "hosts files come from the root"
    );
    let missing = forwarder(&with_geo, &DataRoot::explicit(empty.path()))
        .err()
        .expect("a hosts file missing from the root is an error");
    let expected = empty.path().join("embedder.hosts");
    assert!(
        format!("{missing:#}").contains(&expected.display().to_string()),
        "{missing:#}"
    );
}
