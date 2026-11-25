use super::*;

/// Seeded from the highlighting corpus's routing section: grouped and
/// negated matchers, `must`, `block`, marks and a marked fallback.
const CORPUS: &str = r#"
global { dial_mode: domain }
node { front: 'socks5://192.0.2.10:1080'
    land: 'socks5://192.0.2.11:1080'
    'hk east': 'socks5://192.0.2.12:1080'
    via: front -> land -> 'hk east' }
group {
    123 { policy: fixed } 香港 { policy: min_avg10() } Two Words { policy: round_robin }
    backup { policy: fallback filter: name(land, front) }
    edge { policy: score
        filter: name(via, keyword:front) && !subtag(regex:'^legacy$')
        final: block } }
routing {
    domain(geosite:category-games@cn, suffix:example.test, keyword:ads, full:'*.example.test', regex:'(^|\.)example\.test$') -> edge(must)
    !geosite:cn && !geoip:private && domain:example.test && suffix:test && keyword:lab && full:lab.test && regex:'lab\.test$' -> block
    dip(192.0.2.1, 198.51.100.0/24, 2001:db8::/32, geoip:private) && sip(::1) && pname(curl) && mac(00:11:22:33:44:55) && dscp(0x2e) -> direct(mark: 0x10, must)
    !dip(geoip:private, 203.0.113.0/24) && !domain(suffix:internal.test, keyword:corp) && dport(8443) -> backup
    domain(suffix:blocked.test) -> block
    pname(chrome) -> 香港
    l4proto(tcp, udp) && ipversion(ipv4, 6) && sport(1024-65535) && dport(
        53, 443, 8080-8090) -> edge
    fallback: direct(mark: 16) }
"#;

/// A plain fallback to a group, with `domain++` routing by unverified names.
const FALLBACK_GROUP: &str = r#"
global { dial_mode: 'domain++' }
node { a: 'socks5://192.0.2.20:1080'
    b: 'socks5://192.0.2.21:1080' }
group { proxy { policy: fallback filter: name(a, b) } }
routing {
    dport(22) -> direct(must)
    !domain(geosite:cn) && domain(suffix:cn.test) -> block(must)
    fallback: proxy }
"#;

fn data_root() -> std::path::PathBuf {
    let checkout = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    if checkout.join("geosite.dat").is_file() && checkout.join("geoip.dat").is_file() {
        return checkout.to_path_buf();
    }
    crate::routing::find_geosite_dat()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .expect("geosite.dat and geoip.dat: see AGENTS.md (Current validation guidance)")
}

fn parse(source: &str) -> Config {
    honk_config::parser::parse_dae_config(source).unwrap()
}

fn engine(source: &str) -> Engine {
    Engine::new(parse(source), &data_root()).unwrap()
}

fn flow(network: Network, source: &str, destination: &str) -> Flow {
    Flow {
        network,
        source: source.parse().unwrap(),
        destination: destination.parse().unwrap(),
        domain: None,
        domain_verified: false,
        process_name: None,
        mac: None,
        dscp: None,
    }
}

#[test]
fn modes_never_override_must_or_block() {
    let mut engine = engine(FALLBACK_GROUP);
    let ssh = flow(Network::Tcp, "198.18.0.2:40000", "198.51.100.7:22");
    let mut blocked = flow(Network::Udp, "198.18.0.2:40000", "198.51.100.7:443");
    blocked.domain = Some("video.cn.test".into());
    let other = flow(Network::Tcp, "198.18.0.2:40000", "198.51.100.7:443");

    engine.set_mode(Mode::Direct);
    assert_eq!(engine.decide(&ssh).outbound, "direct");
    assert_eq!(engine.decide(&blocked).outbound, "block");
    let direct = engine.decide(&other);
    assert_eq!(
        (direct.mode, direct.outbound.as_str()),
        (ModeResult::Direct, "direct")
    );

    engine.set_mode(Mode::Global);
    assert_eq!(engine.decide(&other).mode, ModeResult::Block);
    assert_eq!(engine.decide(&other).candidates[0].node, "block");
    engine
        .set_global_target(GlobalTarget::Group("proxy".into()))
        .unwrap();
    let ssh = engine.decide(&ssh);
    assert_eq!(
        (ssh.mode, ssh.must, ssh.outbound.as_str()),
        (ModeResult::Unchanged, true, "direct")
    );
    let blocked = engine.decide(&blocked);
    assert_eq!(
        (blocked.mode, blocked.outbound.as_str()),
        (ModeResult::Unchanged, "block")
    );
    let other = engine.decide(&other);
    assert_eq!(other.mode, ModeResult::Group("proxy".into()));
    assert_eq!(other.candidates[0].node, "a");
    assert_eq!(
        engine.set_global_target(GlobalTarget::Group("missing".into())),
        Err(UnknownTarget)
    );
}

/// A node target is dialled by name, so a name two nodes share is refused.
#[test]
fn a_global_node_target_needs_a_unique_name() {
    let mut config = parse(FALLBACK_GROUP);
    config
        .nodes
        .extend(parse("node { a: 'socks5://192.0.2.99:1080' }").nodes);
    let mut engine = Engine::new(config, &data_root()).unwrap();
    let id = |name| {
        engine
            .config()
            .nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
            .id
    };
    let (a, b) = (id("a"), id("b"));
    engine.set_mode(Mode::Global);
    assert_eq!(
        engine.set_global_target(GlobalTarget::Node(a)),
        Err(UnknownTarget)
    );
    engine.set_global_target(GlobalTarget::Node(b)).unwrap();
    let decision = engine.decide(&flow(Network::Tcp, "198.18.0.2:40000", "198.51.100.7:443"));
    assert_eq!(
        (decision.mode, decision.outbound.as_str(), decision.mark),
        (ModeResult::Node(b), "b", None)
    );
    assert_eq!(decision.candidates[0].node, "b");
}

#[test]
fn missing_process_facts_do_not_match_process_rules() {
    let engine = engine(CORPUS);
    let mut marked = flow(Network::Tcp, "[::1]:40000", "192.0.2.1:443");
    marked.mac = Some("00:11:22:33:44:55".into());
    marked.dscp = Some(0x2e);
    marked.process_name = Some("curl".into());
    let decision = engine.decide(&marked);
    assert_eq!(decision.rule.map(|rule| rule.index), Some(2));
    assert_eq!((decision.must, decision.mark), (true, Some(0x10)));
    marked.process_name = None;
    let decision = engine.decide(&marked);
    assert_eq!(decision.rule.map(|rule| rule.index), Some(6));
}

#[test]
fn geodata_must_be_present_valid_and_complete_in_the_root() {
    let kind = |source: &str, root: &std::path::Path| {
        Engine::new(parse(source), root)
            .err()
            .expect("unusable geodata")
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind)
    };
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        kind(CORPUS, root.path()),
        Some(std::io::ErrorKind::NotFound)
    );
    let missing = Engine::new(parse(CORPUS), root.path()).err().unwrap();
    assert!(missing.to_string().contains("geosite.dat"), "{missing}");
    std::fs::copy(data_root().join("geoip.dat"), root.path().join("geoip.dat")).unwrap();
    std::fs::write(root.path().join("geosite.dat"), b"not a geosite file").unwrap();
    assert_eq!(
        kind(CORPUS, root.path()),
        Some(std::io::ErrorKind::InvalidData)
    );
    let absent = "routing { domain(geosite:honk-absent-category) -> block\n fallback: direct }";
    assert_eq!(
        kind(absent, &data_root()),
        Some(std::io::ErrorKind::InvalidData)
    );
}

#[cfg(feature = "native-api")]
mod parity {
    use std::sync::Arc;

    use super::*;
    use crate::control::connection::routing::build_connection_info;
    use crate::control::connection::tcp::score::tcp_score_context;
    use crate::control::connection::udp::{udp_score_context, udp_target_domain};
    use crate::control::tests::support::test_dns_forwarder;
    use crate::proxy::ProxyRegistry;

    fn flows() -> Vec<Flow> {
        let named = |mut flow: Flow, domain: &str, verified: bool| {
            flow.domain = Some(domain.to_owned());
            flow.domain_verified = verified;
            flow
        };
        let process = |mut flow: Flow, name: &str| {
            flow.process_name = Some(name.to_owned());
            flow
        };
        let tcp = |destination| flow(Network::Tcp, "198.18.0.2:40000", destination);
        let udp = |destination| flow(Network::Udp, "198.18.0.2:40000", destination);
        let mut marked = flow(Network::Tcp, "[::1]:40000", "192.0.2.1:443");
        marked.process_name = Some("curl".into());
        marked.mac = Some("00:11:22:33:44:55".into());
        marked.dscp = Some(0x2e);
        let mut unknown_process = marked.clone();
        unknown_process.process_name = None;
        vec![
            named(tcp("203.0.113.9:443"), "www.example.test", true),
            named(tcp("203.0.113.10:443"), "www.example.test", false),
            named(udp("203.0.113.9:443"), "ads.example.org", true),
            named(tcp("203.0.113.9:443"), "lab.test", true),
            named(tcp("198.51.100.7:8443"), "api.blocked.test", true),
            named(tcp("198.51.100.7:8443"), "intranet.corp.example", true),
            tcp("198.51.100.7:8443"),
            tcp("10.0.0.5:8443"),
            marked,
            unknown_process.clone(),
            process(unknown_process, "chrome-sandbox"),
            process(tcp("198.51.100.7:9000"), "chrome"),
            process(tcp("198.51.100.7:9000"), "unknown-app"),
            tcp("198.51.100.7:22"),
            udp("[2001:db8::5]:53"),
            udp("[2606:4700::1]:443"),
            named(udp("198.51.100.7:443"), "video.cn.test", false),
            named(tcp("198.51.100.7:80"), "www.qq.com", false),
            tcp("198.51.100.7:80"),
        ]
    }

    #[derive(Clone, Copy, Debug)]
    enum Target {
        Unset,
        Node(&'static str),
        Group(&'static str),
    }

    /// Rule, Direct, GLOBAL without a target, and GLOBAL on each target.
    fn modes(targets: &[Target]) -> Vec<(Mode, Target)> {
        let mut modes = vec![
            (Mode::Rule, Target::Unset),
            (Mode::Direct, Target::Unset),
            (Mode::Global, Target::Unset),
            (Mode::Global, Target::Node("direct")),
        ];
        modes.extend(targets.iter().map(|&target| (Mode::Global, target)));
        modes
    }

    const CORPUS_TARGETS: &[Target] = &[
        Target::Node("front"),
        Target::Group("edge"),
        Target::Group("backup"),
    ];
    const FALLBACK_TARGETS: &[Target] = &[Target::Node("a"), Target::Group("proxy")];

    #[derive(Debug, PartialEq, Eq)]
    struct Observed {
        rule: Option<(String, String)>,
        routed: String,
        must: bool,
        outbound: String,
        mark: Option<u32>,
        candidates: Vec<(String, Vec<String>)>,
        speculative: bool,
        context: crate::group::ScoreSelectionContext,
    }

    impl From<(Decision, crate::group::ScoreSelectionContext)> for Observed {
        fn from((decision, context): (Decision, crate::group::ScoreSelectionContext)) -> Self {
            Self {
                rule: decision.rule.map(|rule| (rule.rule_type, rule.payload)),
                routed: decision.routed,
                must: decision.must,
                outbound: decision.outbound,
                mark: decision.mark,
                candidates: decision
                    .candidates
                    .into_iter()
                    .map(|candidate| (candidate.node, candidate.chain))
                    .collect(),
                speculative: decision.speculative,
                context,
            }
        }
    }

    struct Daemon {
        handle: ControlPlaneHandle,
        _native: crate::native_api::observation::NativeObservation,
    }

    /// The daemon's startup order: built-ins, filter assembly, then a control
    /// plane with the native identity owner and its typed mode state.
    async fn daemon(source: &str, mode: Mode, target: Target) -> Daemon {
        let mut config = parse(source);
        config.ensure_builtin_nodes();
        let config = config
            .assemble(honk_config::parser::resolve_group_filters)
            .unwrap();
        let requirements = GeoRequirements::for_traffic(&config.routing.rules);
        let geo = GeoSourceSet::capture_for_admission(&requirements, &data_root(), |_, path| {
            std::fs::read(path).map(Into::into)
        })
        .unwrap();
        let router = Router::from_config_with_geo_sources(&config.routing, &geo).unwrap();
        let mut plane = crate::control::ControlPlane::new(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router,
            Arc::new(ProxyRegistry::default_resolver().unwrap()),
            crate::dns::DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
            test_dns_forwarder(),
        )
        .unwrap();
        let config = Arc::clone(&*plane.config.read().await);
        let native = crate::native_api::observation::NativeObservation::new(&config);
        let catalog = native.core.catalog.snapshot();
        let mut state = ModeState::native();
        state.mode = format!("{mode:?}");
        let target = match target {
            Target::Unset => None,
            Target::Node(name) => {
                let node = config
                    .nodes
                    .iter()
                    .find(|node| node.name == name)
                    .expect("target node");
                Some(ModeTarget::Node {
                    id: node.id,
                    name: node.name.clone(),
                })
            }
            Target::Group(name) => Some(ModeTarget::Group {
                id: catalog.groups.get(name).expect("target group").clone(),
                name: name.to_owned(),
            }),
        };
        if let Some(target) = target {
            state.selection = Selection::Target(Some(target));
        }
        plane.native = Some(Arc::clone(&native.core));
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(state)));
        Daemon {
            handle: plane.spawn_handle(),
            _native: native,
        }
    }

    /// The TCP and UDP handlers' steps for a flow with no eBPF handoff:
    /// reality check result, route, mode override, score context and plan.
    /// The handoff would supply the process facts.
    async fn daemon_decision(handle: &ControlPlaneHandle, flow: &Flow) -> Observed {
        let config = Arc::clone(&*handle.config.read().await);
        let dial_mode = config.global.dial_mode.parse::<DialMode>().unwrap();
        // The handlers' sniff rule (`skip_sniff` in tcp.rs and udp.rs).
        let sniffed = flow.domain.clone().filter(|_| dial_mode_sniffs(dial_mode));
        // The handlers' reality check resolves the name; the flow states the result.
        let outcome = if flow.domain_verified {
            RealityOutcome::ExactMatch
        } else {
            RealityOutcome::Mismatch
        };
        let (domain, domain_verified, _) =
            reality_checked_domain(dial_mode, sniffed, Some(outcome));
        let protocol = match flow.network {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        };
        let mut info = build_connection_info(
            domain.clone(),
            flow.destination,
            flow.source,
            protocol,
            None,
        );
        info.process_name = flow.process_name.clone();
        info.mac = flow.mac.clone();
        info.dscp = flow.dscp;
        let mut route = handle
            .prepare_routing(dial_mode, &info, domain_verified, None, None, false)
            .await;
        let rule = route.matched_rule.take();
        let (routed, must) = (route.outbound.clone(), route.must);
        let mode = handle
            .apply_mode_override(&mut route, OutboundConstraint::Any)
            .await;
        let context = match flow.network {
            Network::Tcp => tcp_score_context(
                flow.destination,
                domain.as_deref(),
                if flow.destination.is_ipv6() {
                    IpVersion::V6
                } else {
                    IpVersion::V4
                },
            ),
            Network::Udp => udp_score_context(
                flow.destination,
                udp_target_domain(&mode.name, domain.as_deref()),
            ),
        };
        let group_manager = handle.group_manager.read().clone();
        let plan = resolve_outbound_plan_for_target(
            &config,
            &group_manager,
            &mode.name,
            &context,
            mode.constraint,
        );
        Observed {
            rule,
            routed,
            must,
            outbound: mode.name,
            mark: route.mark.map(|mark| mark.get()),
            candidates: plan
                .targets
                .into_iter()
                .zip(plan.selection_chains)
                .map(|(target, chain)| (target.node.name, chain))
                .collect(),
            speculative: plan.mode == SelectionPlanMode::ColdUrlTest,
            context,
        }
    }

    #[tokio::test]
    async fn engine_decides_as_the_daemon_for_every_flow_and_mode() {
        let ip_corpus = CORPUS.replace("dial_mode: domain", "dial_mode: ip");
        assert_ne!(ip_corpus, CORPUS);
        let mut compared = 0;
        for (source, targets) in [
            (CORPUS, CORPUS_TARGETS),
            (FALLBACK_GROUP, FALLBACK_TARGETS),
            (ip_corpus.as_str(), CORPUS_TARGETS),
        ] {
            for (mode, target) in modes(targets) {
                let daemon = daemon(source, mode, target).await;
                let mut engine = engine(source);
                engine.set_mode(mode);
                let config = engine.config();
                let target = match target {
                    Target::Unset => None,
                    Target::Node(name) => Some(GlobalTarget::Node(
                        config
                            .nodes
                            .iter()
                            .find(|node| node.name == name)
                            .expect("target node")
                            .id,
                    )),
                    Target::Group(name) => Some(GlobalTarget::Group(name.to_owned())),
                };
                if let Some(target) = target.clone() {
                    engine.set_global_target(target).unwrap();
                }
                for flow in flows() {
                    let expected = daemon_decision(&daemon.handle, &flow).await;
                    let actual = Observed::from(engine.decide_with_context(&flow));
                    assert_eq!(actual, expected, "{mode:?} {target:?} {flow:?}");
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, (7 + 6 + 7) * flows().len());
    }
}
