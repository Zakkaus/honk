//! Health state and probers shared by the daemon and the embedded engine.

use super::*;

/// Per-probe deadline of the periodic health loop.
pub(in crate::control) const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

pub(in crate::control) struct HealthState {
    pub(in crate::control) alive_set: Arc<AliveDialerSet>,
    pub(in crate::control) group_manager: SharedGroupManager,
    pub(in crate::control) outbound_id_map: Arc<parking_lot::RwLock<OutboundHealthIndex>>,
}

/// Registers `config`'s nodes and groups for health checks and builds the
/// group manager that selects by their health.
pub(in crate::control) fn health_state(config: &Config) -> HealthState {
    let alive_set = Arc::new(AliveDialerSet::new().with_so_mark(config.global.effective_so_mark()));
    // Periodic direct health uses a stable bootstrap target; on-demand
    // URL tests still measure their requested URL.
    alive_set.set_direct_check_addr(direct_check_addr(&config.global.bootstrap_resolver));
    let mut reachable = build_outbound_id_map(config);
    let (added, _) = alive_set.sync_registrations(health_registrations(config, &reachable));
    info!(
        "Registered {}/{} nodes for health check ({} skipped: not in any group)",
        added,
        config.nodes.len(),
        config.nodes.len().saturating_sub(added),
    );
    alive_set.sync_idle_groups(&idle_group_registrations(config));
    alive_set.sync_group_check_urls(&group_check_url_registrations(config));
    let group_manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive_set.clone()));
    extend_route_health_dependencies(config, &group_manager, &mut reachable);
    let outbound_id_map = Arc::new(parking_lot::RwLock::new(reachable));
    {
        let map = outbound_id_map.clone();
        alive_set.set_outbound_resolver(Some(Arc::new(move |node_id: uuid::Uuid| {
            map.read().get(&node_id).copied()
        })));
    }
    group_manager.publish_selected_probe_nodes();
    // Custom-URL member resolution: a group's members are probed via
    // their current picks (delay_test_members = tag → representative
    // leaf), so sub-group members are measured through whatever leaf
    // they currently select, and the tag keeps the result. The cell
    // keeps working across reloads (the manager inside is swapped).
    let group_manager = group_manager.into_shared();
    {
        let group_manager = group_manager.clone();
        let probe_interval = Duration::from_secs(config.global.check_interval_secs);
        alive_set.set_score_feedback_factory(move |node_id, context| {
            group_manager
                .read()
                .feedback_for_node(node_id, context)
                .map(|feedback| feedback.with_probe_interval(probe_interval))
        });
    }
    HealthState {
        alive_set,
        group_manager,
        outbound_id_map,
    }
}

/// The dependencies of the HTTP and UDP probers.
pub(in crate::control) struct ProberParts {
    pub(in crate::control) config: Arc<RwLock<Arc<Config>>>,
    pub(in crate::control) proxy_registry: Arc<ProxyRegistry>,
    pub(in crate::control) runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    pub(in crate::control) group_manager: SharedGroupManager,
    pub(in crate::control) stats: Arc<StatsManager>,
    pub(in crate::control) degradations: Arc<crate::degradations::Degradations>,
    /// Resolves a UDP route's recovery target without the DNS fallback.
    pub(in crate::control) recovery_resolver: Option<crate::outbound::ResolveHook>,
    /// Resolves the UDP DNS and QUIC probe targets.
    pub(in crate::control) udp_resolver: Option<crate::outbound::ResolveHook>,
}

/// Installs the HTTP and UDP probers on `alive_set` as `config` sets them.
/// Returns the QUIC Score probe target, if `config` has one.
pub(in crate::control) async fn install_probers(
    alive_set: &AliveDialerSet,
    parts: ProberParts,
) -> Option<Arc<QuicScoreProbeTarget>> {
    let config = parts.config.read().await.clone();
    honk_outbound::tls::set_tls_mode(&config.global.tls_implementation);
    honk_outbound::tls::set_utls_imitate(&config.global.utls_imitate);

    // Configure HTTP-based health checks from config (Go: TcpCheckOption).
    let check_url = config
        .global
        .tcp_check_url
        .first()
        .cloned()
        .unwrap_or_default();
    let check_method = if config.global.tcp_check_http_method.is_empty() {
        "HEAD".to_string()
    } else {
        config.global.tcp_check_http_method.clone()
    };
    let mut prober = super::probers::http::ProxyHttpProber::new(
        parts.config.clone(),
        parts.proxy_registry.clone(),
        parts.runtime_registry.clone(),
        check_method.clone(),
        parts.group_manager.clone(),
    );
    if let Some(resolver) = parts.recovery_resolver {
        prober = prober.with_udp_recovery_resolver(resolver);
    }
    let prober = Arc::new(prober);
    alive_set.set_route_http_probe(prober.clone());
    if !check_url.is_empty() {
        alive_set
            .set_http_probe(prober, check_url, check_method)
            .await;
    } else {
        info!("HTTP health check disabled (no tcp_check_url configured), using TCP connect");
    }

    // Configure UDP health checks (Go: UdpCheckOption): each probe
    // cycle sends one DNS query through the node's own UDP data
    // path, so nodes with working TCP but broken UDP (e.g. an
    // AnyTLS server without UoT) are marked dead for the UDP
    // domains and excluded from UDP selection.
    let dns_raw = config.global.effective_udp_check_dns().to_vec();
    let quic_url = super::probers::quic_probe_url(&config);
    let dns_probe = UdpDnsProbeTarget::new(dns_raw, parts.udp_resolver.clone());
    match tokio::time::timeout(HEALTH_CHECK_TIMEOUT, dns_probe.resolve()).await {
        Ok(Ok((target, _))) => info!("UDP health check enabled (dns={})", target),
        _ => info!("UDP DNS health target initialization deferred to later health checks"),
    }
    let quic_score_target = quic_url.map(|url| {
        Arc::new(QuicScoreProbeTarget::new(
            url,
            parts.udp_resolver,
            parts.degradations,
        ))
    });
    alive_set.set_udp_probe(Arc::new(ProxyUdpProber::new(
        parts.config,
        parts.proxy_registry,
        parts.runtime_registry,
        parts.stats,
        dns_probe,
        quic_score_target.clone(),
        parts.group_manager,
    )));
    quic_score_target
}
