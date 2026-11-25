//! A routing engine for flows that the embedding application captures itself,
//! for example from a TUN descriptor, with no eBPF datapath or daemon.
//!
//! [`Engine::decide`] runs the daemon's userspace decision path for a flow that
//! has no eBPF handoff: the same compiled [`Router`], the same typed mode
//! override ([`ModeState::native_override`]) and the same group plan resolver
//! as the TCP and UDP handlers. The engine owns no sockets, tasks or health
//! probes; subscription nodes are not merged.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

use honk_config::Config;
use honk_outbound::alive::IpVersion;
use honk_outbound::group::SelectionPlanMode;

use super::ControlPlaneHandle;
use super::routing::{RealityOutcome, RoutingDecision, dial_mode_sniffs, reality_checked_domain};
use crate::control::reload::{OutboundConstraint, resolve_outbound_plan_for_target};
use crate::group::{GroupManager, ScoreSelectionContext};
use crate::mode::{ModeOverride, ModeState, ModeTarget, Selection};
use crate::routing::{ConnectionInfo, GeoRequirements, GeoSourceSet, Router};
use honk_config::types::DialMode;

/// Transport of a supplied flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// The facts the routing engine reads for one flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    /// Sniffed TLS, HTTP or QUIC server name; ignored under `dial_mode: ip`,
    /// where the daemon does not sniff.
    pub domain: Option<String>,
    /// Whether the daemon's reality check would trust `domain`: it resolves
    /// to `destination`, or it has records only in the other address family
    /// (`RealityOutcome::OtherFamilyOnly`, which the daemon trusts for
    /// single-stack resolvers). Under `dial_mode: domain` an untrusted domain
    /// is dropped for both routing and score selection.
    pub domain_verified: bool,
    /// `None` when the platform cannot attribute the flow to a process;
    /// `pname` conditions then do not match.
    pub process_name: Option<String>,
    pub mac: Option<String>,
    pub dscp: Option<u8>,
}

/// Outbound mode, as `experimental.clash_api.default_mode` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Rule,
    Global,
    Direct,
}

/// The GLOBAL selection, by identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalTarget {
    Node(uuid::Uuid),
    Group(String),
}

/// The GLOBAL target is not a node or group of the engine's configuration,
/// or names a node whose name another node shares.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown or ambiguous GLOBAL target")]
pub struct UnknownTarget;

/// A routing rule that matched, numbered in configuration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub index: u32,
    pub name: String,
    /// Clash-style rule type and payload, as `/connections` reports them.
    pub rule_type: String,
    pub payload: String,
}

/// What mode handling did to the routed outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeResult {
    /// Rule mode, or a `must` or `block` result, which modes never override.
    Unchanged,
    Direct,
    /// GLOBAL with no target set.
    Block,
    Node(uuid::Uuid),
    Group(String),
}

/// One leaf the flow may be dialled through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub node: String,
    pub node_id: uuid::Uuid,
    /// Groups and node from the selected outbound down to this leaf.
    pub chain: Vec<String>,
}

/// The routing decision for one flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The first matching rule; `None` when the `fallback` action applied.
    pub rule: Option<MatchedRule>,
    /// The rule's outbound before mode handling.
    pub routed: String,
    /// The rule's `must` modifier.
    pub must: bool,
    pub mode: ModeResult,
    /// The outbound after mode handling: a group, a node, `direct` or `block`.
    pub outbound: String,
    /// The direct fwmark; it survives only on a routed `direct` that stays `direct`.
    pub mark: Option<u32>,
    /// Ordered leaves; the daemon dials the first. Empty when no leaf is
    /// eligible, and the daemon then fails the flow rather than going direct.
    /// The engine keeps no health state, so a dead node can come first.
    pub candidates: Vec<Candidate>,
    /// A cold URLTest group: the daemon races up to three leading candidates.
    pub speculative: bool,
}

/// One configuration's routing state, built once; build a new engine to apply
/// a new configuration. It keeps no health state, no group choice made at
/// runtime and no mode across constructions. A new engine starts in Rule mode
/// with no GLOBAL target, whatever `experimental.clash_api.default_mode` and
/// the daemon's stored selection say; the caller sets both on each new engine.
pub struct Engine {
    config: Config,
    dial_mode: DialMode,
    router: Router,
    group_manager: GroupManager,
    /// Group name to identity, the map `ModeState::native_override` reads
    /// from the daemon's catalog (`observe/catalog.rs`). One engine holds one
    /// configuration, so each group's identity is its name.
    groups: HashMap<String, String>,
    mode: ModeState,
}

impl Engine {
    /// Builds an engine from a parsed configuration, assembled as the daemon
    /// assembles it at startup. `data_root` holds `geosite.dat` and
    /// `geoip.dat`; no other location is searched, and a required asset that
    /// is missing, does not parse or lacks a category the rules use is an
    /// error. Subscription nodes must already be merged into `config`, as
    /// `subscription::supervisor::prepare` merges them for the daemon.
    pub fn new(mut config: Config, data_root: &Path) -> anyhow::Result<Self> {
        config.validate()?;
        config.ensure_builtin_nodes();
        let mut config = config.assemble(honk_config::parser::resolve_group_filters)?;
        if config.nodes.iter().any(|node| node.chain_hops().is_some()) {
            config = config.assemble(honk_config::parser::resolve_programmatic_groups)?;
        }
        let dial_mode = config
            .global
            .dial_mode
            .parse::<DialMode>()
            .map_err(|()| anyhow::anyhow!("invalid global.dial_mode"))?;
        let requirements = GeoRequirements::for_traffic(&config.routing.rules);
        let sources = GeoSourceSet::load_from_root(&requirements, data_root)?;
        let router = Router::from_config_with_geo_sources(&config.routing, &sources)?;
        let group_manager = GroupManager::new(&config.groups, &config.nodes);
        let groups = config
            .groups
            .iter()
            .map(|group| (group.name.clone(), group.name.clone()))
            .collect();
        Ok(Self {
            config,
            dial_mode,
            router,
            group_manager,
            groups,
            mode: ModeState::native(),
        })
    }

    /// The assembled configuration. Its node ids and group names are the
    /// valid [`GlobalTarget`]s.
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode.mode = match mode {
            Mode::Rule => "Rule",
            Mode::Global => "Global",
            Mode::Direct => "Direct",
        }
        .to_owned();
    }

    /// Without a target, GLOBAL blocks every flow that is not `must`.
    pub fn set_global_target(&mut self, target: GlobalTarget) -> Result<(), UnknownTarget> {
        let target = match target {
            GlobalTarget::Node(id) => self
                .config
                .nodes
                .iter()
                .find(|node| node.id == id)
                .filter(|target| {
                    // A node target is dialled by name; see `decide`.
                    self.config
                        .nodes
                        .iter()
                        .filter(|node| node.name == target.name)
                        .count()
                        == 1
                })
                .map(|node| ModeTarget::Node {
                    id,
                    name: node.name.clone(),
                }),
            GlobalTarget::Group(name) => {
                self.groups.contains_key(&name).then(|| ModeTarget::Group {
                    id: name.clone(),
                    name,
                })
            }
        }
        .ok_or(UnknownTarget)?;
        self.mode.selection = Selection::Target(Some(target));
        Ok(())
    }

    pub fn decide(&self, flow: &Flow) -> Decision {
        self.decide_with_context(flow).0
    }

    /// [`Engine::decide`] and the score context its plan was resolved for.
    fn decide_with_context(&self, flow: &Flow) -> (Decision, ScoreSelectionContext) {
        // The handlers' sniff rule: a name the daemon would not sniff keys
        // neither routing nor score selection.
        let sniffed = flow
            .domain
            .clone()
            .filter(|_| dial_mode_sniffs(self.dial_mode));
        let (domain, domain_verified, _) = reality_checked_domain(
            self.dial_mode,
            sniffed,
            Some(if flow.domain_verified {
                RealityOutcome::ExactMatch
            } else {
                RealityOutcome::Mismatch
            }),
        );
        let route_with_domain = ControlPlaneHandle::should_route_with_sniffed_domain(
            self.dial_mode,
            domain.as_deref(),
            domain_verified,
        );
        let conn = ConnectionInfo {
            domain: domain.clone().filter(|_| route_with_domain),
            dst_ip: flow.destination.ip(),
            dst_port: flow.destination.port(),
            src_ip: flow.source.ip(),
            src_port: flow.source.port(),
            protocol: match flow.network {
                Network::Tcp => "tcp",
                Network::Udp => "udp",
            },
            process_name: flow.process_name.clone(),
            mac: flow.mac.clone(),
            dscp: flow.dscp,
        };
        let matched = self.router.route_full(&conn);
        let action = matched
            .as_ref()
            .map_or(self.router.fallback(), |hit| hit.action);
        let rule = matched.as_ref().map(|hit| MatchedRule {
            index: hit.rule_id,
            name: hit.rule_name.to_owned(),
            rule_type: hit.rule_type.to_owned(),
            payload: hit.rule_payload.to_owned(),
        });
        let mut route = RoutingDecision {
            outbound: action.outbound.clone(),
            must: action.must,
            mark: action.mark,
            matched_rule: None,
            reroute_by_sniffed_domain: false,
            #[cfg(feature = "native-api")]
            native_route: None,
        };
        let routed = route.outbound.clone();

        let mode = self
            .mode
            .native_override(&routed, route.must, &self.config, &self.groups);
        // The daemon pins a node target by identity with
        // `OutboundConstraint::Node`, declared in `control/reload/`
        // (CONTRIBUTING.md §2) and compiled only with `native-api`; using it
        // here would widen that cfg. This configuration never changes and
        // `set_global_target` admits only uniquely named nodes, so the name
        // selects the same node.
        let outbound = match &mode {
            ModeOverride::Unchanged => routed.clone(),
            ModeOverride::Direct => "direct".to_owned(),
            ModeOverride::Block => "block".to_owned(),
            ModeOverride::Node(id) => self
                .config
                .nodes
                .iter()
                .find(|node| node.id == *id)
                .expect("validated mode target")
                .name
                .clone(),
            ModeOverride::Group(name) => name.clone(),
        };
        route.apply_final_outbound((outbound != routed).then(|| outbound.clone()));

        let context = match flow.network {
            Network::Tcp => super::tcp::score::tcp_score_context(
                flow.destination,
                domain.as_deref(),
                if flow.destination.is_ipv6() {
                    IpVersion::V6
                } else {
                    IpVersion::V4
                },
            ),
            Network::Udp => super::udp::udp_score_context(
                flow.destination,
                super::udp::udp_target_domain(&outbound, domain.as_deref()),
            ),
        };
        let plan = resolve_outbound_plan_for_target(
            &self.config,
            &self.group_manager,
            &outbound,
            &context,
            OutboundConstraint::Any,
        );
        let candidates = plan
            .targets
            .into_iter()
            .zip(plan.selection_chains)
            .map(|(target, chain)| Candidate {
                node: target.node.name,
                node_id: target.node.id,
                chain,
            })
            .collect();

        let decision = Decision {
            rule,
            routed,
            must: route.must,
            mode: match mode {
                ModeOverride::Unchanged => ModeResult::Unchanged,
                ModeOverride::Direct => ModeResult::Direct,
                ModeOverride::Block => ModeResult::Block,
                ModeOverride::Node(id) => ModeResult::Node(id),
                ModeOverride::Group(name) => ModeResult::Group(name),
            },
            outbound,
            mark: route.mark.map(|mark| mark.get()),
            candidates,
            speculative: plan.mode == SelectionPlanMode::ColdUrlTest,
        };
        (decision, context)
    }
}

#[cfg(test)]
mod tests;
