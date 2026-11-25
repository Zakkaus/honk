use super::*;
use crate::dns::forwarder::build_dns_query;
use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
use crate::dns::query::{DnsRequestMeta, IngressProfile};
use crate::dns::service::DnsService;
use honk_outbound::proxy::{PacketRejection, packet_rejection};

#[derive(Default)]
struct AnswerPool {
    queries: AtomicUsize,
}

#[async_trait]
impl DnsUpstreamPool for AnswerPool {
    async fn query(&self, _: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        let mut response = raw_query.to_vec();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        Ok(response)
    }
}

fn answer_forwarder(pool: Arc<AnswerPool>) -> Arc<DnsForwarder> {
    let mut config = Config::default();
    config.dns.routing.fallback = "default".to_owned();
    Arc::new(DnsForwarder::new(
        pool,
        Arc::new(Mutex::new(DnsCache::new(32))),
        Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("valid DNS router")),
    ))
}

fn answer_service(pool: Arc<AnswerPool>) -> (Arc<DnsRuntime>, DnsService) {
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
        forwarder: answer_forwarder(pool),
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            1,
            Arc::new(Router::new(&[], "direct").unwrap()),
        )),
        outbound_runtime: None,
        transport: Arc::new(ObservedTransport::default()),
    });
    let provider = Arc::new(DnsServiceProvider::new(Arc::clone(&runtime)));
    (runtime, DnsService::with_provider(provider))
}

fn captured_query() -> (Vec<u8>, DnsRequestMeta, IngressProfile) {
    (
        build_dns_query("captured.example", 1),
        DnsRequestMeta::new(
            Some("192.0.2.10".parse().unwrap()),
            Some("192.0.2.53:53".parse().unwrap()),
        ),
        IngressProfile::Udp {
            advertised_size: 1232,
        },
    )
}

#[tokio::test]
async fn captured_query_returns_the_admitted_outcome_without_keeping_its_lease() {
    let (query, metadata, ingress) = captured_query();
    let (admitted_runtime, admitted_service) = answer_service(Arc::default());
    let lease = admitted_service.try_acquire_runtime().unwrap();
    let admitted = admitted_service
        .resolve_client_outcome_with_runtime(&lease, &query, metadata, ingress, None)
        .await
        .unwrap();
    drop(lease);
    assert_eq!(admitted_runtime.lease_count(), 0);

    let pool = Arc::new(AnswerPool::default());
    let (runtime, service) = answer_service(Arc::clone(&pool));
    let captured = service
        .resolve_outcome_with_context(&query, metadata, ingress)
        .await
        .unwrap();

    assert_eq!(runtime.lease_count(), 0, "the outcome holds no lease");
    assert_eq!(pool.queries.load(Ordering::SeqCst), 1);
    assert_eq!(captured.status(), OutcomeStatus::Accepted);
    assert_eq!(captured.response_class(), ResponseClass::Positive);
    assert_eq!(captured.provenance(), Provenance::Upstream);
    assert_eq!(captured.domain(), "captured.example");
    assert_eq!(
        captured.answer_ips(),
        ["192.0.2.7".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(captured.status(), admitted.status());
    assert_eq!(captured.response_class(), admitted.response_class());
    assert_eq!(captured.provenance(), admitted.provenance());
    assert_eq!(captured.rendered(), admitted.rendered());
    assert_eq!(captured.reusable(), admitted.reusable());
}

#[tokio::test]
async fn captured_query_takes_a_generation_query_permit() {
    let (query, metadata, ingress) = captured_query();
    let pool = Arc::new(AnswerPool::default());
    let (runtime, service) = answer_service(Arc::clone(&pool));
    let held = (0..crate::dns::runtime::MAX_CONCURRENT_QUERIES)
        .map(|_| runtime.try_acquire_query().unwrap())
        .collect::<Vec<_>>();

    let error = service
        .resolve_outcome_with_context(&query, metadata, ingress)
        .await
        .unwrap_err();
    assert_eq!(packet_rejection(&error), Some(PacketRejection::Capacity));
    assert_eq!(pool.queries.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.lease_count(), 0);

    drop(held);
    service
        .resolve_outcome_with_context(&query, metadata, ingress)
        .await
        .unwrap();
    assert_eq!(pool.queries.load(Ordering::SeqCst), 1);
    let released = (0..crate::dns::runtime::MAX_CONCURRENT_QUERIES)
        .map_while(|_| runtime.try_acquire_query().ok())
        .count();
    assert_eq!(
        released,
        crate::dns::runtime::MAX_CONCURRENT_QUERIES,
        "the query permit is released with the outcome"
    );
}

#[tokio::test]
async fn paused_dns_refuses_a_captured_query_before_upstream() {
    let (query, metadata, ingress) = captured_query();
    let pool = Arc::new(AnswerPool::default());
    let (runtime, service) = answer_service(Arc::clone(&pool));
    let provider = service.provider().unwrap();
    provider.begin_pause();

    let error = service
        .resolve_outcome_with_context(&query, metadata, ingress)
        .await
        .unwrap_err();
    assert_eq!(packet_rejection(&error), Some(PacketRejection::Cancelled));
    assert_eq!(pool.queries.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.lease_count(), 0);
    provider.finish_pause().await.unwrap();
}

#[tokio::test]
async fn standalone_service_returns_a_captured_outcome() {
    let (query, metadata, ingress) = captured_query();
    let pool = Arc::new(AnswerPool::default());
    let service = DnsService::with_forwarder(answer_forwarder(Arc::clone(&pool)));

    let outcome = service
        .resolve_outcome_with_context(&query, metadata, ingress)
        .await
        .unwrap();

    assert_eq!(outcome.status(), OutcomeStatus::Accepted);
    assert_eq!(
        outcome.answer_ips(),
        ["192.0.2.7".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(pool.queries.load(Ordering::SeqCst), 1);
}
