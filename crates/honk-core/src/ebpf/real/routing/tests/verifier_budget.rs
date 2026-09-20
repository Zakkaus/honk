//! The #280 policy shape: two `sip && dip && dport` rules ahead of fifteen
//! process-name rules, MAC rules between and after them, and later source,
//! destination and domain rules that keep every fact in use until the end.
//!
//! With facts kept as map pointers the verifier could not merge the paths
//! through the process-name chains and this policy exceeded the
//! 1,000,000-instruction budget on Linux 6.12; with facts copied out as
//! bitmap values the issue's own policy verifies in about 53,000.

use super::{assert_route, decision, domain_entry, input, object, outbound_ids, rule};
use crate::control::routing_matcher::RoutingPushPlan;
use crate::ebpf::EbpfBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::{Router, golden};
use honk_config::routing::{RoutingCondition, RoutingNotCondition, RoutingRule};
use honk_config::types::DialMode;
use honk_ebpf_common::DaeParam;

fn process(names: &[&str]) -> RoutingCondition {
    RoutingCondition {
        process_name: names.iter().map(|name| name.to_string()).collect(),
        ..Default::default()
    }
}

fn issue_280_rules() -> Vec<RoutingRule> {
    let benchmark = |port: &str| RoutingCondition {
        source_ip: vec!["198.18.81.2/32".into()],
        ip: vec!["198.18.80.2/32".into()],
        port: vec![port.into()],
        ..Default::default()
    };
    let mut rules = vec![
        rule("bench-1", benchmark("15201"), "proxy", 0, true),
        rule("bench-2", benchmark("15202"), "proxy", 0, true),
        rule(
            "dns-daemons",
            RoutingCondition {
                protocol: vec!["udp".into()],
                port: vec!["53".into()],
                ..process(&["dnsmasq", "systemd-resolved"])
            },
            "block",
            0,
            true,
        ),
    ];
    for names in [
        &["mosdns", "honk-subsribe", "honk-tool"][..],
        &["NetworkManager"],
        &["systemd-networkd"],
        &["systemd-resolved"],
        &["dhcpcd"],
    ] {
        rules.push(rule(names[0], process(names), "block", 0, true));
    }
    rules.push(rule(
        "lan-macs",
        RoutingCondition {
            mac: vec![
                "02:00:00:00:00:01".into(),
                "02:00:00:00:00:02".into(),
                "02:00:00:00:00:03".into(),
                "02:00:00:00:00:04".into(),
            ],
            ..Default::default()
        },
        "block",
        0,
        true,
    ));
    rules.push(rule(
        "one-mac",
        RoutingCondition {
            mac: vec!["02:00:00:00:00:05".into()],
            ..Default::default()
        },
        "block",
        0,
        true,
    ));
    rules.push(rule(
        "dscp",
        RoutingCondition {
            dscp: vec!["4".into()],
            ..Default::default()
        },
        "block",
        0,
        true,
    ));
    for name in [
        "qbittorrent",
        "iris",
        "iris-meta",
        "sing-box",
        "mihomo",
        "frpc",
        "einat",
        "qemu-system-x86",
        "pacman",
    ] {
        rules.push(rule(name, process(&[name]), "block", 0, true));
    }
    rules.extend([
        rule(
            "one-more-mac",
            RoutingCondition {
                mac: vec!["02:00:00:00:00:06".into()],
                ..Default::default()
            },
            "block",
            0,
            true,
        ),
        rule(
            "printer",
            RoutingCondition {
                source_ip: vec!["198.51.100.24/32".into()],
                not: RoutingNotCondition {
                    port: vec!["53".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "block",
            0,
            true,
        ),
        rule(
            "private",
            RoutingCondition {
                ip: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
                ..Default::default()
            },
            "block",
            0,
            true,
        ),
        rule(
            "domain-direct",
            RoutingCondition {
                domain_suffix: vec!["example.net".into(), "example.org".into()],
                ..Default::default()
            },
            "block",
            0,
            false,
        ),
        rule(
            "one-port",
            RoutingCondition {
                port: vec!["14588".into()],
                ..Default::default()
            },
            "block",
            0,
            true,
        ),
        rule(
            "region",
            RoutingCondition {
                ip: vec!["203.0.113.0/24".into()],
                ..Default::default()
            },
            "proxy",
            0,
            false,
        ),
        rule(
            "domain-proxy",
            RoutingCondition {
                domain_suffix: vec!["example.com".into()],
                ..Default::default()
            },
            "proxy",
            0,
            false,
        ),
        rule(
            "web",
            RoutingCondition {
                port: vec!["22".into(), "80".into(), "443".into(), "8080".into()],
                ..Default::default()
            },
            "proxy",
            0,
            false,
        ),
    ]);
    rules
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn facts_ahead_of_long_process_chains_stay_within_the_verifier_budget() {
    let rules = issue_280_rules();
    let router = Router::new(&rules, "direct").unwrap();
    let plan =
        RoutingPushPlan::compile(&router, &outbound_ids(), "direct", DialMode::Domain).unwrap();

    let mut benchmark = golden::connection();
    benchmark.src_ip = "198.18.81.2".parse().unwrap();
    benchmark.dst_ip = "198.18.80.2".parse().unwrap();
    benchmark.dst_port = 15201;
    let mut torrent = golden::connection();
    torrent.process_name = Some("qbittorrent".into());
    let mut lan = golden::connection();
    lan.mac = Some("02:00:00:00:00:06".into());
    let mut private = golden::connection();
    private.dst_ip = "192.168.7.7".parse().unwrap();
    let mut proxied = golden::connection();
    proxied.domain = Some("www.example.com".into());
    proxied.dst_ip = "203.0.113.9".parse().unwrap();
    let mut fallback = golden::connection();
    fallback.dst_port = 9999;

    let learned = [domain_entry(&router, &proxied, "www.example.com")];
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    backend.publish_routing_plan(&plan, &learned).unwrap();

    for (label, connection, expected) in [
        ("first rule", &benchmark, decision(2, 0, true, 0, 0)),
        ("process name", &torrent, decision(1, 0, true, 0, 11)),
        ("MAC after the chains", &lan, decision(1, 0, true, 0, 20)),
        (
            "destination after the chains",
            &private,
            decision(1, 0, true, 0, 22),
        ),
        (
            "region with a learned domain",
            &proxied,
            decision(2, 0, false, 1, 25),
        ),
        ("fallback", &fallback, decision(0, 0, false, 0, u32::MAX)),
    ] {
        assert_route(&mut backend, label, &input(connection), expected);
    }
}
