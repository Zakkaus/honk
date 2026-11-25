//! An embedder's explicit data root reaches the control plane, the router and
//! the DNS forwarder it builds, instead of the process data root.

use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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
