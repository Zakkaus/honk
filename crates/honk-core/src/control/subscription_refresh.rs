//! Subscription refresh for an embedder that runs neither the control-command
//! loop nor the subscription supervisor.

use super::{ControlPlane, ReloadOutcome};
use crate::subscription::{SubscriptionManager, SubscriptionStore, SubscriptionUserinfo};

/// How a refreshed body reached the running configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionPublication {
    /// The provider's effective nodes were already active; nothing was rebuilt.
    Unchanged { generation: u64 },
    /// The nodes were published in this generation.
    Committed { generation: u64 },
    /// The nodes were published, but the runtime committed degraded; the
    /// daemon reports this as `publication_degraded`.
    CommittedDegraded { generation: u64 },
    /// Admission refused the nodes and the active ones were kept. `code` is
    /// the configuration diagnostic behind the refusal, when there is one.
    Rejected { code: Option<&'static str> },
    /// A reload replaced, disabled or removed the provider while its body was
    /// in flight, so nothing was published.
    Replaced,
}

/// The result of [`ControlPlane::refresh_subscription`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRefresh {
    pub publication: SubscriptionPublication,
    /// The provider's nodes in the active configuration afterwards.
    pub node_count: usize,
    pub userinfo: SubscriptionUserinfo,
}

/// Why [`ControlPlane::refresh_subscription`] published nothing before a body arrived.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionRefreshError {
    #[error("subscription {0} is not configured")]
    NotConfigured(uuid::Uuid),
    #[error("subscription '{0}' is disabled")]
    Disabled(String),
    /// The fetch or the body failed; active nodes are kept. `code` is the
    /// supervisor's code for the same failure (`fetch_failed`, `route_unavailable`).
    #[error("{error}")]
    Fetch {
        code: &'static str,
        error: anyhow::Error,
    },
}

impl ControlPlane {
    /// Fetch one configured, enabled subscription and publish its nodes
    /// through the merge the daemon's supervisor uses, without the control
    /// command channel.
    ///
    /// The body is fetched, stored in `store` when one is given, and its entry
    /// diagnostics are logged and published as the supervisor does. A store
    /// records this configuration's enabled providers first, as the
    /// supervisor's reconcile does. Routed fetches use this control plane's
    /// outbounds, so a manager serves one control plane. Publication runs
    /// under the reload lock on the caller's task, like
    /// [`ControlPlane::reload_runtime_config`]. Dropping the future during the
    /// fetch or while it waits for the lock publishes nothing and leaves the
    /// lock free. Once it holds the lock it runs the reload transaction,
    /// which, as for `reload_runtime_config`, must be driven to completion;
    /// dropping it there is not supported. The daemon runs one fetch per
    /// provider at a time; an embedder keeps the same rule, because
    /// concurrent calls for one provider publish in lock order, not fetch
    /// order.
    pub async fn refresh_subscription(
        &self,
        manager: &SubscriptionManager,
        store: Option<&SubscriptionStore>,
        subscription_id: uuid::Uuid,
    ) -> Result<SubscriptionRefresh, SubscriptionRefreshError> {
        let config = self.config.read().await.clone();
        let subscription = config
            .subscriptions
            .iter()
            .find(|subscription| subscription.id == subscription_id)
            .cloned()
            .ok_or(SubscriptionRefreshError::NotConfigured(subscription_id))?;
        if !subscription.enabled {
            return Err(SubscriptionRefreshError::Disabled(subscription.name));
        }
        if let Some(store) = store {
            // The supervisor records this set on every reconcile; a store
            // write may evict the body of any provider outside it.
            store.set_enabled(
                config
                    .subscriptions
                    .iter()
                    .filter(|subscription| subscription.enabled),
            );
        }
        manager.route_through(crate::download_route::SharedOutbounds {
            router: self.traffic_router(),
            config: self.config_handle(),
            group_manager: self.group_manager(),
            proxy_registry: self.proxy_registry(),
            runtime_registry: self.runtime_registry(),
        });
        let mut diagnostics = Vec::new();
        let fetched = manager.fetch_content(&subscription, &mut diagnostics).await;
        let fetched = match fetched {
            Ok((nodes, content, userinfo)) => {
                SubscriptionManager::persist_content(
                    &subscription,
                    store,
                    content,
                    &mut diagnostics,
                    0,
                )
                .await;
                Ok((nodes, userinfo))
            }
            Err(error) => Err(error),
        };
        honk_config::diagnostic::report_detailed_diagnostics(&diagnostics);
        let (nodes, userinfo) = fetched.map_err(|error| SubscriptionRefreshError::Fetch {
            code: crate::subscription::failure_code(&error),
            error,
        })?;
        let (result, node_count) = self
            .merge_fetched_subscription_nodes(&subscription, nodes, diagnostics)
            .await;
        let publication = match result {
            None => SubscriptionPublication::Replaced,
            Some(Ok(ReloadOutcome::Noop { generation })) => {
                SubscriptionPublication::Unchanged { generation }
            }
            Some(Ok(ReloadOutcome::Committed { generation })) => {
                SubscriptionPublication::Committed { generation }
            }
            Some(Ok(ReloadOutcome::CommittedDegraded { generation })) => {
                SubscriptionPublication::CommittedDegraded { generation }
            }
            Some(Ok(ReloadOutcome::Rejected)) => SubscriptionPublication::Rejected { code: None },
            Some(Err(error)) => {
                crate::report_runtime_admission_error(&error);
                SubscriptionPublication::Rejected {
                    code: Some(error.diagnostic.code),
                }
            }
        };
        Ok(SubscriptionRefresh {
            publication,
            node_count,
            userinfo,
        })
    }
}

#[cfg(test)]
mod tests;
