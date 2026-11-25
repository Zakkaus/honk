use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Mutex, watch};

use super::cache::DnsCache;
use super::forwarder::DnsForwarder;
use super::outcome::DnsOutcome;
use super::query::{DnsRequestMeta, IngressProfile};
use super::runtime::{DnsServiceProvider, RuntimeLease};

mod cache_control;
#[cfg(feature = "native-api")]
mod diagnostic;
mod name_resolution;
#[cfg(feature = "native-api")]
pub(crate) use diagnostic::{DiagnosticError, DiagnosticFailure};
#[cfg(feature = "native-api")]
pub(crate) use name_resolution::PinnedNameResolver;

#[derive(Clone)]
pub struct DnsService {
    backend: Arc<DnsServiceBackend>,
    flush_generation: watch::Sender<u64>,
    pub(crate) observer: crate::observe::DnsObserver,
    pub(crate) audit: crate::audit::DnsAudit,
}

enum DnsServiceBackend {
    Runtime(Arc<DnsServiceProvider>),
    Standalone(Arc<DnsForwarder>),
}

struct OperationToken {
    generation: u64,
    updates: watch::Receiver<u64>,
    observer: crate::observe::DnsOperation,
}

#[derive(Debug, thiserror::Error)]
#[error("DNS operation cancelled by cache flush at generation {generation}")]
struct OperationCancelled {
    generation: u64,
}

impl OperationToken {
    async fn run<T>(
        &mut self,
        operation: impl Future<Output = T>,
    ) -> Result<T, OperationCancelled> {
        if *self.updates.borrow() != self.generation {
            return Err(OperationCancelled {
                generation: self.generation,
            });
        }
        let operation = self.observer.scope(operation);
        tokio::pin!(operation);
        // Operation first avoids a watch waiter per ready query; a flush
        // published before completion was observed still cancels it.
        tokio::select! {
            biased;
            result = &mut operation => match self.updates.has_changed() {
                Ok(false) => Ok(result),
                Ok(true) | Err(_) => Err(OperationCancelled {
                    generation: self.generation,
                }),
            },
            _ = self.updates.changed() => Err(OperationCancelled {
                generation: self.generation,
            }),
        }
    }
}

impl DnsService {
    #[cfg(feature = "native-api")]
    pub(crate) fn attach_observer(&self, observer: std::sync::Weak<crate::observe::DnsRecorder>) {
        self.observer.attach(observer);
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn observation_enabled(&self) -> bool {
        self.observer.recording()
    }

    pub fn with_forwarder(forwarder: Arc<DnsForwarder>) -> Self {
        let (flush_generation, _) = watch::channel(0);
        Self {
            backend: Arc::new(DnsServiceBackend::Standalone(forwarder)),
            flush_generation,
            observer: Default::default(),
            audit: Default::default(),
        }
    }

    pub(crate) fn with_provider(provider: Arc<DnsServiceProvider>) -> Self {
        let (flush_generation, _) = watch::channel(0);
        Self {
            backend: Arc::new(DnsServiceBackend::Runtime(provider)),
            flush_generation,
            observer: Default::default(),
            audit: Default::default(),
        }
    }

    pub async fn resolve(
        &self,
        raw_query: &[u8],
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        self.resolve_with_context(raw_query, DnsRequestMeta::EMPTY, ingress)
            .await
    }

    pub async fn resolve_with_context(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        let mut operation = self.operation();
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                let lease = provider.try_acquire()?;
                operation
                    .run(lease.run(std::pin::pin!(lease
                            .runtime()
                            .forwarder()
                            .resolve_strict_with_context_and_profile(
                                raw_query, metadata, ingress,
                            ))))
                    .await??
            }
            DnsServiceBackend::Standalone(forwarder) => {
                operation
                    .run(
                        forwarder
                            .resolve_strict_with_context_and_profile(raw_query, metadata, ingress),
                    )
                    .await?
            }
        }
    }

    /// Resolves one captured client query and returns honk's typed outcome.
    ///
    /// The query runs under the current generation's lease and query permit,
    /// as an admitted transparent query does; both are released before this
    /// returns, so a held outcome never delays generation retirement. The
    /// caller owns framing and the reply. [`packet_rejection`] finds
    /// [`PacketRejection::Capacity`] for a saturated generation and
    /// [`PacketRejection::Cancelled`] for a retired one;
    /// [`DnsForwardError::Overloaded`] is the daemon's `REFUSED` case. No
    /// domain route is projected.
    ///
    /// [`packet_rejection`]: honk_outbound::proxy::packet_rejection
    /// [`PacketRejection::Capacity`]: honk_outbound::proxy::PacketRejection::Capacity
    /// [`PacketRejection::Cancelled`]: honk_outbound::proxy::PacketRejection::Cancelled
    /// [`DnsForwardError::Overloaded`]: crate::dns::forwarder::DnsForwardError::Overloaded
    pub async fn resolve_outcome_with_context(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> anyhow::Result<DnsOutcome> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                let lease = provider.try_acquire()?;
                // The query semaphore is never closed, so it fails only when
                // the generation is saturated.
                let _permit = lease
                    .runtime()
                    .try_acquire_query()
                    .map_err(|_| honk_outbound::proxy::PacketRejection::Capacity)?;
                self.resolve_client_outcome_with_runtime(&lease, raw_query, metadata, ingress, None)
                    .await
            }
            DnsServiceBackend::Standalone(forwarder) => {
                let mut operation = self.operation();
                operation
                    .run(
                        forwarder
                            .resolve_outcome_with_context_and_profile(raw_query, metadata, ingress),
                    )
                    .await?
                    .map_err(Into::into)
            }
        }
    }

    pub(crate) async fn resolve_client_outcome_with_runtime(
        &self,
        runtime: &RuntimeLease,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
        evidence: Option<&mut crate::dns::outcome::RouteSource>,
    ) -> anyhow::Result<DnsOutcome> {
        let mut operation = self.operation();
        operation
            .run(
                runtime.run(std::pin::pin!(runtime.runtime().forwarder().resolve_inner(
                    raw_query,
                    metadata,
                    ingress,
                    &crate::dns::forwarder::ResolveOptions::default(),
                    crate::dns::forwarder::ResolveMode::Strict,
                    evidence,
                ))),
            )
            .await??
            .map_err(Into::into)
    }

    pub async fn flush_cache(&self) -> anyhow::Result<bool> {
        Ok(self
            .invalidate_cache(crate::dns::cache::CacheInvalidation::All)
            .await?
            .persistent)
    }

    pub fn cache(&self) -> Arc<Mutex<DnsCache>> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => provider.current().cache(),
            DnsServiceBackend::Standalone(forwarder) => forwarder.cache(),
        }
    }

    pub(crate) fn provider(&self) -> Option<Arc<DnsServiceProvider>> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => Some(Arc::clone(provider)),
            DnsServiceBackend::Standalone(_) => None,
        }
    }

    pub(crate) fn try_acquire_runtime(
        &self,
    ) -> Result<RuntimeLease, super::runtime::DnsUnavailable> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => provider.try_acquire(),
            DnsServiceBackend::Standalone(_) => {
                unreachable!("runtime admission requires a runtime DNS service")
            }
        }
    }

    pub fn forwarder(&self) -> Arc<DnsForwarder> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => Arc::clone(provider.current().forwarder()),
            DnsServiceBackend::Standalone(forwarder) => Arc::clone(forwarder),
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn geo_assets(&self) -> Vec<crate::routing::GeoAssetSnapshot> {
        self.forwarder().routing_snapshot().geo_assets().to_vec()
    }

    fn operation(&self) -> OperationToken {
        let updates = self.flush_generation.subscribe();
        let generation = *updates.borrow();
        OperationToken {
            generation,
            updates,
            observer: self.observer.operation(),
        }
    }
}
