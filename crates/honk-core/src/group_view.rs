//! What the Clash API and the embedded engine report and measure for groups:
//! the member a group shows as chosen, and honk's URL test through a node or
//! through each member of a group.

use std::sync::Arc;
use std::time::Duration;

use honk_config::group::GroupPolicy;
use honk_config::node::{Group, Node};
use honk_outbound::alive::{
    AliveDialerSet, IpVersion, ProbeCancellation, ProbeDomain, ProbeMeasurement, ProbeTicket,
};
use honk_outbound::group::{GroupManager, SelectionNetwork, SharedGroupManager};
use honk_outbound::proxy::ProxyRegistry;
use honk_outbound::runtime::{OutboundRuntimeRegistry, SharedRuntimeRegistry};
use honk_outbound::urltest::{
    urltest_group_with_feedback, urltest_node_in_generation_with_feedback,
};

/// The member tag `group` shows as chosen for TCP: an explicit Selector
/// choice or an automatic group's pin, else the policy's current pick, else
/// its first member. `score_verified` is the Score verification's TCP pick.
pub(crate) fn displayed_member(
    group: &Group,
    group_manager: &GroupManager,
    score_verified: Option<String>,
) -> String {
    let node_names = group_manager.node_names_in_group(&group.name);
    match (
        group.policy,
        group_manager.get_selector_choice(&group.name, SelectionNetwork::Tcp),
    ) {
        (_, Some(choice)) => choice,
        (GroupPolicy::Selector, None) => group
            .default
            .clone()
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        (GroupPolicy::URLTest, None) => group_manager
            .get_urltest_selection(&group.name)
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        // Round-robin has no stable selection to display; show the first.
        (GroupPolicy::LoadBalance, None) => node_names.first().cloned().unwrap_or_default(),
        (GroupPolicy::Fallback, None) => group_manager
            .get_fallback_selection(&group.name)
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        (GroupPolicy::Score, None) => score_verified
            .or_else(|| {
                group_manager.get_score_selection_for_network(&group.name, SelectionNetwork::Tcp)
            })
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
    }
}

/// The last measured TCP latency of a real node and when it was taken;
/// synthetic failure placeholders are skipped.
pub(crate) fn last_latency(
    alive_set: &AliveDialerSet,
    node: &Node,
) -> Option<(Duration, std::time::SystemTime)> {
    alive_set.get_last_real_sample(node.id, ProbeDomain::Tcp, IpVersion::V4)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NodeDelayError {
    #[error("no handler for the node protocol")]
    NoHandler,
    #[error("An error occurred in the delay test: {0}")]
    Failed(anyhow::Error),
}

/// A node and its probe ticket, captured together.
pub(crate) struct NodeDelayCapture {
    group_manager: Arc<GroupManager>,
    generation: Arc<OutboundRuntimeRegistry>,
    ticket: ProbeTicket,
}

impl NodeDelayCapture {
    pub(crate) fn new(
        alive_set: &AliveDialerSet,
        runtime_registry: &SharedRuntimeRegistry,
        group_manager: &SharedGroupManager,
        node: &Node,
    ) -> Self {
        let manager = group_manager.read();
        let (generation, ticket) = alive_set.clash_node_ticket(node, runtime_registry);
        Self {
            group_manager: Arc::clone(&manager),
            generation,
            ticket,
        }
    }

    /// Measures `url` through `node` and records the latency as health
    /// evidence when the node's published dial path is still the one measured.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run(
        &self,
        node: &Node,
        alive_set: &AliveDialerSet,
        runtime_registry: &SharedRuntimeRegistry,
        proxy_registry: &ProxyRegistry,
        url: &str,
        timeout: Duration,
        cancel: ProbeCancellation,
    ) -> Result<ProbeMeasurement, NodeDelayError> {
        let entry = proxy_registry
            .find(node.protocol())
            .ok_or(NodeDelayError::NoHandler)?;
        let tcp = entry.tcp.clone();
        let warmable = entry.warmable.clone();
        let measurement = urltest_node_in_generation_with_feedback(
            &self.generation,
            node,
            tcp.as_ref(),
            warmable.as_deref(),
            url,
            timeout,
            &self.group_manager,
            cancel,
        )
        .await
        .map_err(NodeDelayError::Failed)?;
        alive_set.record_urltest_latency(
            runtime_registry,
            &self.generation,
            &self.ticket,
            measurement,
        );
        Ok(measurement)
    }
}

/// A group's members and their probe tickets, captured together.
pub(crate) struct GroupDelayCapture {
    /// Member tag and the leaf it is measured through, in member order.
    pub(crate) members: Vec<(String, Node)>,
    tickets: Vec<ProbeTicket>,
    group_manager: Arc<GroupManager>,
    generation: Arc<OutboundRuntimeRegistry>,
}

impl GroupDelayCapture {
    pub(crate) fn new(
        alive_set: &AliveDialerSet,
        runtime_registry: &SharedRuntimeRegistry,
        group_manager: &SharedGroupManager,
        name: &str,
    ) -> Self {
        let manager = group_manager.read();
        let registry = runtime_registry.read();
        let members = manager.delay_test_members(name);
        let tickets = members
            .iter()
            .map(|(_, leaf)| alive_set.probe_ticket(leaf.id))
            .collect();
        Self {
            members,
            tickets,
            group_manager: Arc::clone(&manager),
            generation: Arc::clone(&registry),
        }
    }

    /// Measures every member concurrently and returns `(leaf name, result)`
    /// in member order. A URLTest group then reselects from the new
    /// latencies while its manager is still the published one.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run(
        &self,
        name: &str,
        alive_set: &Arc<AliveDialerSet>,
        runtime_registry: &SharedRuntimeRegistry,
        proxy_registry: &Arc<ProxyRegistry>,
        published: &SharedGroupManager,
        url: &str,
        timeout: Duration,
        cancel: ProbeCancellation,
    ) -> Vec<(String, anyhow::Result<Duration>)> {
        let leaves: Vec<_> = self
            .members
            .iter()
            .zip(&self.tickets)
            .map(|((_, leaf), ticket)| (leaf, ticket.clone()))
            .collect();
        let results = urltest_group_with_feedback(
            &leaves,
            &self.generation,
            runtime_registry,
            proxy_registry,
            alive_set,
            url,
            timeout,
            Arc::clone(&self.group_manager),
            cancel.clone(),
        )
        .await;
        if !cancel.is_cancelled() {
            reselect_urltest(published, &self.group_manager, name);
        }
        results
    }

    #[cfg(feature = "clash-api")]
    pub(crate) fn group_manager(&self) -> &GroupManager {
        &self.group_manager
    }
}

fn reselect_urltest(published: &SharedGroupManager, captured: &Arc<GroupManager>, name: &str) {
    if captured.get_group_policy(name) != Some(GroupPolicy::URLTest) {
        return;
    }
    // Keep the manager published through selection and its activity update.
    let published = published.read();
    if Arc::ptr_eq(&published, captured) {
        let _ = captured.select_node_for_domain(name, ProbeDomain::Tcp, IpVersion::V4);
    }
}
