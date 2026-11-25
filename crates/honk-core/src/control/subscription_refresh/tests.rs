use super::*;
use crate::control::ControlCommand;
use crate::control::drain::DrainTracker;
use crate::control::tests::support::control_plane;
use crate::subscription::{
    SubscriptionAuthorizations, parse_subscription_content_with_diagnostics,
};
use honk_config::Config;
use honk_config::node::{Group, GroupPolicy};
use honk_config::subscription::Subscription;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

/// Two nodes and one entry the parser skips with a diagnostic.
const BODY: &str =
    "socks5://127.0.0.1:1080#first\nsocks5://127.0.0.1:1081#second\nunknown://entry\n";
const USERINFO: &str = "subscription-userinfo: upload=1; download=2; total=3; expire=4\r\n";

fn ok(body: &str, headers: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn read_request(stream: &mut tokio::net::TcpStream) {
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0, "client closed before its request ended");
        request.extend_from_slice(&buffer[..read]);
    }
}

/// Reports a request's arrival, then holds its reply until opened.
type Gate = (oneshot::Sender<()>, oneshot::Receiver<()>);

/// An origin that answers one request per entry, in order. A gate makes that
/// answer wait: the request's arrival is reported, and the reply goes out
/// when the gate opens.
async fn origin(replies: Vec<(String, Option<Gate>)>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/feed", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for (reply, gate) in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            if let Some((arrived, open)) = gate {
                arrived.send(()).unwrap();
                open.await.unwrap();
            }
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    (url, task)
}

fn provider_config(id: uuid::Uuid, url: &str) -> Config {
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.subscriptions = vec![Subscription {
        id,
        name: "provider".into(),
        url: url.into(),
        download_detour: "direct".into(),
        ..Default::default()
    }];
    config.groups = vec![Group {
        name: "proxy".into(),
        policy: GroupPolicy::Selector,
        ..Default::default()
    }];
    config
}

async fn running_plane(config: Config) -> ControlPlane {
    let mut cp = control_plane(config);
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", "Proxy"),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();
    cp
}

async fn active(cp: &ControlPlane) -> Arc<Config> {
    Arc::clone(&*cp.config_handle().read().await)
}

async fn provider_nodes(cp: &ControlPlane, id: uuid::Uuid) -> Vec<(uuid::Uuid, String)> {
    active(cp)
        .await
        .nodes
        .iter()
        .filter(|node| node.subscription_id == Some(id))
        .map(|node| (node.id, node.name.clone()))
        .collect()
}

#[tokio::test]
async fn a_refresh_publishes_what_the_daemon_merge_publishes() {
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(BODY, USERINFO), None)]).await;
    let config = provider_config(id, &url);

    let embedded = running_plane(config.clone()).await;
    let manager = SubscriptionManager::new().unwrap();
    let refresh = embedded
        .refresh_subscription(&manager, None, id)
        .await
        .unwrap();
    server.await.unwrap();

    let mut daemon = running_plane(config.clone()).await;
    let mut authorizations = SubscriptionAuthorizations::new(&config.subscriptions).unwrap();
    let revision = authorizations.revision(id).unwrap();
    let mut diagnostics = Vec::new();
    let nodes = parse_subscription_content_with_diagnostics(
        &config.subscriptions[0],
        BODY,
        &mut diagnostics,
    )
    .unwrap();
    let (result, reply) = oneshot::channel();
    assert!(
        daemon
            .dispatch_control_command(
                ControlCommand::MergeSubscription {
                    subscription_id: id,
                    revision,
                    nodes,
                    diagnostics,
                    result,
                },
                &DrainTracker::new(),
                &mut authorizations,
            )
            .await
    );
    let reply = reply.await.unwrap();

    assert!(matches!(
        refresh.publication,
        SubscriptionPublication::Committed { .. }
    ));
    assert!(matches!(reply.outcome, ReloadOutcome::Committed { .. }));
    assert_eq!(refresh.node_count, 2);
    assert_eq!(refresh.node_count, reply.node_count);
    assert_eq!(
        refresh.userinfo,
        SubscriptionUserinfo {
            upload: Some(1),
            download: Some(2),
            total: Some(3),
            expire: Some(4),
        }
    );
    assert_eq!(
        provider_nodes(&embedded, id).await,
        provider_nodes(&daemon, id).await
    );
    assert_eq!(active(&embedded).await.groups, active(&daemon).await.groups);
    assert_eq!(
        format!("{:?}", embedded.diagnostics_handle().read().buckets),
        format!("{:?}", daemon.diagnostics_handle().read().buckets)
    );
    assert!(
        embedded
            .diagnostics_handle()
            .read()
            .buckets
            .providers
            .iter()
            .any(|(provider, diagnostics)| *provider == id
                && diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "unsupported-subscription-entry"))
    );
}

#[tokio::test]
async fn a_routed_provider_is_fetched_through_this_control_plane() {
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(BODY, ""), None)]).await;
    let mut config = provider_config(id, &url);
    config.subscriptions[0].download_detour = "routing".into();
    let cp = running_plane(config).await;

    let refresh = cp
        .refresh_subscription(&SubscriptionManager::new().unwrap(), None, id)
        .await
        .unwrap();
    server.await.unwrap();

    assert!(matches!(
        refresh.publication,
        SubscriptionPublication::Committed { .. }
    ));
    assert_eq!(provider_nodes(&cp, id).await.len(), 2);
}

#[tokio::test]
async fn refreshing_the_same_body_again_rebuilds_nothing() {
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(BODY, ""), None), (ok(BODY, ""), None)]).await;
    let cp = running_plane(provider_config(id, &url)).await;
    let manager = SubscriptionManager::new().unwrap();

    let first = cp.refresh_subscription(&manager, None, id).await.unwrap();
    let published = active(&cp).await;
    let second = cp.refresh_subscription(&manager, None, id).await.unwrap();
    server.await.unwrap();

    assert!(matches!(
        first.publication,
        SubscriptionPublication::Committed { .. }
    ));
    assert!(matches!(
        second.publication,
        SubscriptionPublication::Unchanged { .. }
    ));
    assert_eq!(second.node_count, 2);
    assert!(Arc::ptr_eq(&published, &active(&cp).await));
}

#[tokio::test]
async fn a_provider_replaced_during_the_fetch_publishes_nothing() {
    for change in ["url", "disabled", "removed"] {
        let id = uuid::Uuid::new_v4();
        let (arrived_tx, arrived) = oneshot::channel();
        let (open, open_rx) = oneshot::channel();
        let (url, server) = origin(vec![(ok(BODY, ""), Some((arrived_tx, open_rx)))]).await;
        let cp = running_plane(provider_config(id, &url)).await;
        let manager = SubscriptionManager::new().unwrap();

        let replace = async {
            arrived.await.unwrap();
            let mut candidate = active(&cp).await.as_ref().clone();
            match change {
                "url" => candidate.subscriptions[0].url = format!("{url}?v=2"),
                "disabled" => candidate.subscriptions[0].enabled = false,
                _ => candidate.subscriptions.clear(),
            }
            // Only the SIGHUP path may change subscription workers.
            let mut authorizations =
                SubscriptionAuthorizations::new(&active(&cp).await.subscriptions).unwrap();
            let outcome = cp
                .apply_sighup_config(
                    candidate,
                    Vec::new(),
                    &DrainTracker::new(),
                    &mut authorizations,
                    #[cfg(feature = "native-api")]
                    None,
                    #[cfg(feature = "native-api")]
                    None,
                )
                .await
                .unwrap();
            assert!(outcome.accepted(), "{change}");
            open.send(()).unwrap();
        };
        let (refresh, ()) = tokio::join!(cp.refresh_subscription(&manager, None, id), replace);
        server.await.unwrap();

        let refresh = refresh.unwrap();
        assert_eq!(
            refresh.publication,
            SubscriptionPublication::Replaced,
            "{change}"
        );
        assert_eq!(refresh.node_count, 0, "{change}");
        assert!(provider_nodes(&cp, id).await.is_empty(), "{change}");
    }
}

#[tokio::test]
async fn publication_waits_for_the_reload_lock() {
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(BODY, ""), None)]).await;
    let cp = running_plane(provider_config(id, &url)).await;
    let manager = SubscriptionManager::new().unwrap();
    let before = active(&cp).await;

    let reload = cp.reload_lock.lock().await;
    let refresh = cp.refresh_subscription(&manager, None, id);
    tokio::pin!(refresh);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut refresh)
            .await
            .is_err()
    );
    server.await.unwrap();
    assert!(Arc::ptr_eq(&before, &active(&cp).await));

    drop(reload);
    let refresh = refresh.await.unwrap();
    assert!(matches!(
        refresh.publication,
        SubscriptionPublication::Committed { .. }
    ));
    assert_eq!(provider_nodes(&cp, id).await.len(), 2);
}

#[tokio::test]
async fn a_failed_fetch_keeps_the_active_nodes_and_reports_its_code() {
    let id = uuid::Uuid::new_v4();
    let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let (url, server) = origin(vec![(ok(BODY, ""), None), (not_found.into(), None)]).await;
    let cp = running_plane(provider_config(id, &url)).await;
    let manager = SubscriptionManager::new().unwrap();
    cp.refresh_subscription(&manager, None, id).await.unwrap();
    let published = active(&cp).await;

    let error = cp
        .refresh_subscription(&manager, None, id)
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(
        matches!(
            error,
            SubscriptionRefreshError::Fetch {
                code: "fetch_failed",
                ..
            }
        ),
        "{error:?}"
    );
    assert!(Arc::ptr_eq(&published, &active(&cp).await));
}

#[tokio::test]
async fn only_a_configured_enabled_provider_is_refreshed() {
    let id = uuid::Uuid::new_v4();
    let mut config = provider_config(id, "http://127.0.0.1:9/feed");
    config.subscriptions[0].enabled = false;
    let cp = running_plane(config).await;
    let manager = SubscriptionManager::new().unwrap();

    let other = uuid::Uuid::new_v4();
    assert!(matches!(
        cp.refresh_subscription(&manager, None, other).await,
        Err(SubscriptionRefreshError::NotConfigured(missing)) if missing == other
    ));
    assert!(matches!(
        cp.refresh_subscription(&manager, None, id).await,
        Err(SubscriptionRefreshError::Disabled(name)) if name == "provider"
    ));
}

#[tokio::test]
async fn a_store_keeps_the_body_and_evicts_providers_no_longer_configured() {
    const MIB: usize = 1024 * 1024;
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(BODY, ""), None)]).await;
    let config = provider_config(id, &url);
    let cp = running_plane(config.clone()).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    // Bodies left by removed providers fill the 32 MiB store.
    for index in 0..4 {
        let removed = Subscription {
            url: format!("https://example.invalid/removed{index}"),
            ..Default::default()
        };
        store
            .store_content(&removed, "#".repeat(8 * MIB))
            .await
            .unwrap();
    }

    cp.refresh_subscription(&SubscriptionManager::new().unwrap(), Some(&store), id)
        .await
        .unwrap();
    server.await.unwrap();

    let restored = store
        .load_nodes(&config.subscriptions[0])
        .await
        .unwrap()
        .expect("the refreshed body is stored");
    assert_eq!(
        restored
            .iter()
            .map(|node| (node.id, node.name.clone()))
            .collect::<Vec<_>>(),
        provider_nodes(&cp, id).await
    );
}

#[tokio::test]
async fn a_commit_that_cannot_reopen_admission_is_reported_degraded() {
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(BODY, ""), None)]).await;
    let cp = running_plane(provider_config(id, &url)).await;
    let manager = SubscriptionManager::new().unwrap();
    {
        let mut ebpf = cp.ebpf.write().await;
        ebpf.clear_datapath_flags_write_log();
        ebpf.arm_datapath_flags_write_fault(2).unwrap();
    }

    let refresh = cp.refresh_subscription(&manager, None, id).await.unwrap();
    server.await.unwrap();
    assert!(
        matches!(
            refresh.publication,
            SubscriptionPublication::CommittedDegraded { .. }
        ),
        "{:?}",
        refresh.publication
    );
    assert_eq!(refresh.node_count, 2);
    assert_eq!(provider_nodes(&cp, id).await.len(), 2);
}

#[tokio::test]
async fn a_body_admission_refuses_is_rejected_with_its_code() {
    // The parser drops a node the body repeats, so the duplicate that
    // admission refuses is a static node the body publishes again.
    const LINK: &str = "socks5://127.0.0.1:1080#same";
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(LINK, ""), None)]).await;
    let mut config = provider_config(id, &url);
    config
        .nodes
        .push(honk_config::node::Node::from_share_link(LINK).unwrap());
    let cp = running_plane(config).await;
    let manager = SubscriptionManager::new().unwrap();
    let before = active(&cp).await;

    let refresh = cp.refresh_subscription(&manager, None, id).await.unwrap();
    server.await.unwrap();
    assert!(
        matches!(
            refresh.publication,
            SubscriptionPublication::Rejected {
                code: Some("duplicate-node-id")
            }
        ),
        "{:?}",
        refresh.publication
    );
    assert!(Arc::ptr_eq(&before, &active(&cp).await));
    assert_eq!(refresh.node_count, 0);
}

#[tokio::test]
async fn a_refresh_dropped_before_it_holds_the_reload_lock_publishes_nothing() {
    let id = uuid::Uuid::new_v4();
    let (url, server) = origin(vec![(ok(BODY, ""), None), (ok(BODY, ""), None)]).await;
    let cp = running_plane(provider_config(id, &url)).await;
    let manager = SubscriptionManager::new().unwrap();
    let before = active(&cp).await;

    let reload = cp.reload_lock.lock().await;
    {
        let refresh = cp.refresh_subscription(&manager, None, id);
        tokio::pin!(refresh);
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut refresh)
                .await
                .is_err()
        );
    }
    drop(reload);
    assert!(Arc::ptr_eq(&before, &active(&cp).await));

    let refresh = tokio::time::timeout(
        Duration::from_secs(5),
        cp.refresh_subscription(&manager, None, id),
    )
    .await
    .expect("the dropped refresh left the reload lock free")
    .unwrap();
    server.await.unwrap();
    assert!(matches!(
        refresh.publication,
        SubscriptionPublication::Committed { .. }
    ));
    assert_eq!(provider_nodes(&cp, id).await.len(), 2);
}
