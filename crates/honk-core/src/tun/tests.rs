use super::*;
use crate::control::netstack::{PacketOwner, PacketScope, RuntimeLimits};
use std::os::unix::net::UnixDatagram;

#[tokio::test]
async fn stale_topology_readiness_rearms_before_the_next_notification() {
    let (reader, writer) = UnixDatagram::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    writer.set_nonblocking(true).unwrap();
    // SAFETY: the socket keeps its descriptor unchanged until deregistration.
    let mut reader = unsafe { AsyncFd::register(reader) }
        .map_err(io::Error::from)
        .unwrap();
    writer.send(b"stale").unwrap();
    drop(reader.readable().await.unwrap());
    assert_eq!(reader.get_ref().recv(&mut [0; 16]).unwrap(), 5);
    let (armed, waiting) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut armed = Some(armed);
        poll_fn(|cx| {
            match poll_topology(&mut reader, cx, |socket| match socket.recv(&mut [0; 16]) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error),
            })
            .unwrap()
            {
                Poll::Pending => {
                    if let Some(armed) = armed.take() {
                        let _ = armed.send(());
                    }
                    Poll::Pending
                }
                Poll::Ready(changed) => {
                    assert!(changed, "cached readiness must clear and park, not spin");
                    Poll::Ready(())
                }
            }
        })
        .await;
    });
    waiting.await.unwrap();
    writer.send(b"changed").unwrap();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("the new topology event must wake the parked owner")
        .unwrap();
}

fn scope() -> (PacketScope, PacketOwner, Arc<MemoryBudget>) {
    let budget = MemoryBudget::new(8 << 20);
    let mut config = honk_netstack::Config::new([19; 32]);
    config.mode = honk_netstack::Mode::Transparent {
        exclude: Default::default(),
    };
    config.mtu = 1500;
    config.max_flows = 8;
    config.memory_limit = 2 << 20;
    let (scope, owner) = PacketScope::new_with_output(
        config,
        Arc::clone(&budget),
        RuntimeLimits {
            max_slots: 8,
            control_frames: 4,
            bulk_frames: 4,
            max_waiters: 4,
        },
        Instant::now(),
        TX_CAPS,
        u16::MAX as usize,
    )
    .unwrap();
    (scope, owner, budget)
}

async fn driven_endpoints() -> (
    PacketEndpoints,
    PacketEndpointOwner,
    PacketDriver,
    PacketScope,
    Arc<MemoryBudget>,
) {
    let (scope, scope_owner, budget) = scope();
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    let plane = crate::control::tests::support::control_plane(config);
    let (endpoints, mut owner, mut drivers) = PacketEndpoints::start_driven(
        plane,
        vec![(scope.clone(), scope_owner)],
        1,
        None,
        ScopeId::HOST,
    )
    .await
    .unwrap();
    let mut driver = drivers.pop().unwrap();
    poll_fn(|cx| {
        driver.service(cx, Instant::now());
        owner.poll_ready(cx)
    })
    .await
    .unwrap();
    (endpoints, owner, driver, scope, budget)
}

#[tokio::test]
async fn close_racing_udp_admission_preserves_the_joined_shutdown_outcome() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for port in [53, 443] {
            for abandon in [false, true] {
                let (endpoints, mut owner, driver, scope, budget) = driven_endpoints().await;
                let mut driver = Some(driver);
                let admission = AtomicBool::new(true);
                let source = "192.0.2.1:41000".parse().unwrap();
                let destination = std::net::SocketAddr::from(([198, 51, 100, 1], port));
                let mut packet = [0; 128];
                let length = honk_netstack::wire::udp::emit_packet(
                    &mut packet,
                    source,
                    destination,
                    b"close-race",
                )
                .unwrap();
                let seed = !wire::checksum::Checksum::pseudo(
                    source.ip(),
                    destination.ip(),
                    wire::PROTO_UDP,
                    length - 20,
                )
                .finish();
                packet[26..28].copy_from_slice(&seed.to_be_bytes());
                let mut received_source = false;
                std::thread::scope(|threads| {
                    let (close, requested) = std::sync::mpsc::sync_channel(0);
                    let closing = &endpoints;
                    threads.spawn(move || {
                        requested.recv().unwrap();
                        closing.close();
                    });
                    admit_packet(
                        &endpoints,
                        scope.scope(),
                        &packet[..length],
                        RxMeta {
                            csum: Csum::Partial {
                                start: 20,
                                offset: 6,
                            },
                            gso: None,
                        },
                        Instant::now(),
                        |_, _| {
                            let allowed =
                                admission.load(Ordering::Acquire) && !endpoints.is_closing();
                            assert!(allowed);
                            received_source = true;
                            close.send(()).unwrap();
                            // close publishes CLOSING before waiting for this scope mutex.
                            let deadline = Instant::now() + Duration::from_secs(5);
                            while !endpoints.is_closing() {
                                assert!(Instant::now() < deadline, "close did not publish");
                                std::thread::yield_now();
                            }
                            allowed
                        },
                    )
                    .expect("an admitted UDP racing endpoint close must not fail the TUN owner");
                });
                assert!(received_source);
                assert!(endpoints.is_closing());
                assert!(!endpoints.retains_source(scope.scope(), source.ip()));
                if abandon {
                    drop(driver.take());
                }
                let (plane, result) = poll_fn(|cx| {
                    if let Some(driver) = &mut driver {
                        driver.service(cx, Instant::now());
                    }
                    owner.poll_join_plane(cx)
                })
                .await
                .unwrap();
                if abandon {
                    result.expect_err("a close must preserve supervisor failure");
                } else {
                    result.expect("ordinary joined stop must preserve supervisor success");
                }
                drop((plane, endpoints, owner, driver, scope));
                assert_eq!(budget.used(), 0);
            }
        }
    })
    .await
    .expect("both normal stop and failed supervisor must join the original packet owners");
}

#[tokio::test]
async fn admission_errors_without_endpoint_close_remain_failures() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, mut owner, mut driver, scope, budget) = driven_endpoints().await;
        let mut packet = [0; 128];
        let source = "192.0.2.1:41000".parse().unwrap();
        let length = honk_netstack::wire::udp::emit_packet(
            &mut packet,
            source,
            "198.51.100.1:53".parse().unwrap(),
            b"source-closed",
        )
        .unwrap();
        scope.shutdown(false);
        let error = admit_packet(
            &endpoints,
            scope.scope(),
            &packet[..length],
            RxMeta::VERIFY,
            Instant::now(),
            |_, _| true,
        )
        .expect_err("a closed UDP53 source hold alone is not a graceful endpoint stop");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(!endpoints.is_closing());
        let error = admit_packet(
            &endpoints,
            honk_datapath::ScopeId::HOST,
            &packet[..length],
            RxMeta::VERIFY,
            Instant::now(),
            |_, _| true,
        )
        .expect_err("an unowned scope must remain an admission failure");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        endpoints.close();
        let (plane, result) = poll_fn(|cx| {
            driver.service(cx, Instant::now());
            owner.poll_join_plane(cx)
        })
        .await
        .unwrap();
        result.unwrap();
        drop((plane, endpoints, owner, driver, scope));
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("a genuine admission error must still permit joined cleanup");
}

async fn output(scope: &PacketScope) -> OutputLease {
    scope
        .datagram_sender("198.51.100.1:53".parse().unwrap())
        .send_to(b"unchanged-lease", "192.0.2.1:41000".parse().unwrap())
        .await
        .unwrap();
    scope.drive(Instant::now());
    scope.next_output().await.unwrap()
}

#[tokio::test]
async fn writable_readiness_retries_the_same_lease_without_new_input() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (scope, owner, budget) = scope();
        use honk_netstack::wire::tcp;
        let mut syn = [0; 128];
        let length = tcp::emit_packet(
            &mut syn,
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
            &tcp::Header {
                src_port: 41000,
                dst_port: 443,
                seq: 19,
                ack: 0,
                flags: tcp::SYN,
                window: 4096,
                urgent: 0,
                options: tcp::Options::default(),
            },
            [&[], &[]],
        )
        .unwrap();
        assert_eq!(
            scope.receive(&syn[..length], Instant::now()),
            honk_netstack::Rx::Consumed
        );
        let (_, mut flow) = scope.poll_accept().unwrap();
        scope.drive(Instant::now());
        let synack = scope.next_output().await.unwrap();
        let ip = wire::parse_ip(synack.packet()).unwrap();
        let sequence = tcp::parse(&synack.packet()[ip.payload])
            .unwrap()
            .0
            .seq
            .wrapping_add(1);
        drop(synack);
        let length = tcp::emit_packet(
            &mut syn,
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
            &tcp::Header {
                src_port: 41000,
                dst_port: 443,
                seq: 20,
                ack: sequence,
                flags: tcp::ACK,
                window: u16::MAX,
                urgent: 0,
                options: tcp::Options::default(),
            },
            [&[], &[]],
        )
        .unwrap();
        assert_eq!(
            scope.receive(&syn[..length], Instant::now()),
            honk_netstack::Rx::Consumed
        );
        tokio::io::AsyncWriteExt::write_all(&mut flow, &[5; 8192])
            .await
            .unwrap();
        scope.drive(Instant::now());
        let lease = scope.next_output().await.unwrap();
        assert_eq!(lease.flow_id(), Some(flow.flow_id()));
        assert!(lease.transmit().gso.is_some());
        assert!(matches!(lease.transmit().csum, TxCsum::Partial { .. }));
        let original = lease.packet().to_vec();
        let pointer = lease.packet().as_ptr();
        let identity = (
            lease.scope(),
            lease.flow_id(),
            lease.class(),
            lease.transmit(),
        );
        let header = vnet_header(lease.packet(), lease.transmit()).unwrap();
        let mut pending = std::array::from_fn(|_| None);
        pending[0] = Some(lease);
        let (writer, reader) = UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let filler = [7; 2048];
        loop {
            match writer.send(&filler) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill socket: {error}"),
            }
        }
        let mut attempts = 0;
        let mut bytes = 0;
        let mut interrupted = false;
        assert_eq!(
            flush_pending(
                Framing::Vnet,
                &mut pending,
                &mut attempts,
                &mut bytes,
                Instant::now(),
                |actual_header, packet| {
                    assert_eq!(actual_header, &header);
                    assert_eq!(packet, original);
                    if !interrupted {
                        interrupted = true;
                        Err(io::ErrorKind::Interrupted.into())
                    } else {
                        write_packet(writer.as_raw_fd(), actual_header, packet)
                    }
                }
            )
            .unwrap(),
            (true, false)
        );
        assert_eq!(attempts, 2);
        assert_eq!(bytes, 0);
        let retained = pending[0].as_ref().unwrap();
        assert_eq!(retained.packet().as_ptr(), pointer);
        assert_eq!(
            (
                retained.scope(),
                retained.flow_id(),
                retained.class(),
                retained.transmit()
            ),
            identity
        );
        assert_eq!(retained.packet(), original);
        scope.shutdown(true);
        drop(flow);
        let joined = owner.run();
        tokio::pin!(joined);
        assert!(
            futures::poll!(&mut joined).is_pending(),
            "exported output still owns completion"
        );
        // SAFETY: the Unix socket keeps its descriptor unchanged while registered.
        let writer = unsafe { AsyncFd::register(writer) }
            .map_err(io::Error::from)
            .unwrap();
        let retry = poll_fn(|cx| {
            let mut attempts = 0;
            let mut bytes = 0;
            let runnable = poll_flush(
                Framing::Vnet,
                &writer,
                cx,
                &mut pending,
                &mut attempts,
                &mut bytes,
                Instant::now(),
                || true,
            )
            .unwrap();
            if pending.iter().all(Option::is_none) {
                Poll::Ready(())
            } else {
                if runnable {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
        });
        tokio::pin!(retry);
        assert!(futures::poll!(&mut retry).is_pending());
        let mut received = [0; RX_BYTES];
        loop {
            match reader.recv(&mut received) {
                Ok(length) => assert_eq!(&received[..length], filler),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("drain filler: {error}"),
            }
        }
        retry.await;
        let length = reader.recv(&mut received).unwrap();
        assert_eq!(&received[..VNET_BYTES], header);
        assert_eq!(&received[VNET_BYTES..length], original);
        assert_eq!(
            reader.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        joined.await;
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("writable readiness alone must retry and release the original output");
}

#[tokio::test]
async fn closed_capture_does_not_write_a_pending_record() {
    let (scope, owner, budget) = scope();
    let lease = output(&scope).await;
    let pointer = lease.packet().as_ptr();
    let mut pending = std::array::from_fn(|_| None);
    pending[0] = Some(lease);
    let (writer, reader) = UnixDatagram::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    reader.set_nonblocking(true).unwrap();
    // SAFETY: this socket owns an unchanged descriptor until deregistration.
    let writer = unsafe { AsyncFd::register(writer) }
        .map_err(io::Error::from)
        .unwrap();
    let mut attempts = 0;
    let mut bytes = 0;
    assert!(
        poll_flush(
            Framing::Vnet,
            &writer,
            &mut Context::from_waker(std::task::Waker::noop()),
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            || false
        )
        .unwrap()
    );
    assert_eq!((attempts, bytes), (0, 0));
    assert_eq!(pending[0].as_ref().unwrap().packet().as_ptr(), pointer);
    assert_eq!(
        reader.recv(&mut [0; 2048]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    scope.shutdown(true);
    let joined = owner.run();
    tokio::pin!(joined);
    assert!(futures::poll!(&mut joined).is_pending());
    drop(pending);
    joined.await;
    drop(scope);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn short_zero_and_fatal_writes_never_replay_or_release_as_success() {
    for outcome in [
        Ok(0),
        Ok(1),
        Ok(VNET_BYTES - 1),
        Ok(VNET_BYTES),
        Ok(VNET_BYTES + 1),
        Err(io::ErrorKind::InvalidInput),
        Err(io::ErrorKind::BrokenPipe),
    ] {
        let (scope, owner, budget) = scope();
        let lease = output(&scope).await;
        let original = lease.packet().to_vec();
        let mut pending = std::array::from_fn(|_| None);
        pending[0] = Some(lease);
        let mut calls = 0;
        let mut attempts = 0;
        let mut bytes = 0;
        let error = flush_pending(
            Framing::Vnet,
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |header, packet| {
                calls += 1;
                assert_eq!(header, &[0; VNET_BYTES]);
                assert_eq!(packet, original);
                outcome.map_err(io::Error::from)
            },
        )
        .unwrap_err();
        assert_eq!(
            calls, 1,
            "no whole-record or suffix retry after a boundary failure"
        );
        assert_eq!(bytes, 0);
        if outcome.is_ok() {
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        }
        assert_eq!(pending[0].as_ref().unwrap().packet(), original);
        scope.shutdown(true);
        let joined = owner.run();
        tokio::pin!(joined);
        assert!(futures::poll!(&mut joined).is_pending());
        drop(pending[0].take());
        joined.await;
        drop(scope);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn interrupted_writes_keep_one_lease_with_a_finite_syscall_budget() {
    let (scope, owner, budget) = scope();
    let lease = output(&scope).await;
    let pointer = lease.packet().as_ptr();
    let mut pending = std::array::from_fn(|_| None);
    pending[0] = Some(lease);
    let mut attempts = 0;
    let mut bytes = 0;
    let (blocked, runnable) = flush_pending(
        Framing::Vnet,
        &mut pending,
        &mut attempts,
        &mut bytes,
        Instant::now(),
        |_, _| Err(io::ErrorKind::Interrupted.into()),
    )
    .unwrap();
    assert!(!blocked && runnable);
    assert!((1..=BATCH * 2).contains(&attempts));
    assert_eq!(bytes, 0);
    assert_eq!(pending[0].as_ref().unwrap().packet().as_ptr(), pointer);
    let mut attempts = 0;
    assert_eq!(
        flush_pending(
            Framing::Vnet,
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |header, packet| Ok(header.len() + packet.len())
        )
        .unwrap(),
        (false, false)
    );
    assert_eq!(attempts, 1);
    assert!(pending.iter().all(Option::is_none));
    scope.shutdown(true);
    owner.run().await;
    drop(scope);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn accepted_prefix_is_not_rolled_back_when_the_next_record_blocks() {
    let (scope, owner, budget) = scope();
    let mut pending = std::array::from_fn(|_| None);
    pending[0] = Some(output(&scope).await);
    pending[1] = Some(output(&scope).await);
    let pointer = pending[1].as_ref().unwrap().packet().as_ptr();
    let length = VNET_BYTES + pending[0].as_ref().unwrap().packet().len();
    let mut attempts = 0;
    let mut bytes = 0;
    let mut calls = 0;
    assert_eq!(
        flush_pending(
            Framing::Vnet,
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |header, packet| {
                calls += 1;
                if calls == 1 {
                    Ok(header.len() + packet.len())
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            }
        )
        .unwrap(),
        (true, false)
    );
    assert_eq!(attempts, 2);
    assert_eq!(bytes, length);
    assert!(pending[0].is_none());
    assert_eq!(pending[1].as_ref().unwrap().packet().as_ptr(), pointer);
    drop(pending);
    scope.shutdown(true);
    owner.run().await;
    drop(scope);
    assert_eq!(budget.used(), 0);
}

#[test]
fn fd_records_require_exact_ip_extent_and_bounded_turns() {
    let mut ipv4 = vec![0; 20];
    ipv4[0] = 0x45;
    ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
    let mut ipv6 = vec![0; 40];
    ipv6[0] = 0x60;
    for packet in [ipv4, ipv6] {
        assert!(exact_record(&packet));
        assert!(!exact_record(&packet[..packet.len() - 1]));
        let mut padded = packet;
        padded.push(0);
        assert!(!exact_record(&padded));
    }
    assert!(!exact_record(&[0; 40]));
    let now = Instant::now();
    assert!(turn_limit(BATCH, 0, now, BATCH));
    assert!(turn_limit(1, TURN_BYTES, now, BATCH));
    assert!(turn_limit(8, 0, now - TURN_TIME, BATCH));
    assert!(!turn_limit(0, 0, now - TURN_TIME, BATCH));
    assert!(!turn_limit(7, 0, now - TURN_TIME, BATCH));
}

#[test]
fn vnet_byte_vectors_validate_family_extents_and_partial_udp_without_uso() {
    let tcp4 = [
        0x45, 0, 0, 44, 0, 0, 0x40, 0, 64, 6, 0x4e, 0x96, 192, 0, 2, 1, 198, 51, 100, 1, 0xa0,
        0x28, 1, 0xbb, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0, 1, 2, 3, 4,
    ];
    let tcp4_header = [1, 1, 40, 0, 0xb4, 5, 20, 0, 16, 0];
    let expected = RxMeta {
        csum: Csum::Partial {
            start: 20,
            offset: 16,
        },
        gso: Some(GsoRx {
            kind: GsoKind::Tcp,
            size: 1460,
        }),
    };
    assert_eq!(vnet_meta(&tcp4_header, &tcp4), Some(expected));
    assert_eq!(
        vnet_header(
            &tcp4,
            Transmit {
                len: tcp4.len(),
                gso: Some(honk_netstack::GsoTx {
                    kind: GsoKind::Tcp,
                    size: 1460,
                    hdr_len: 40
                }),
                csum: TxCsum::Partial {
                    start: 20,
                    offset: 16
                },
                flow: None,
                source: None,
            }
        )
        .unwrap(),
        tcp4_header
    );
    let mut linear_payload_header = tcp4_header;
    linear_payload_header[2] = 44;
    assert_eq!(vnet_meta(&linear_payload_header, &tcp4), Some(expected));
    for (field, value) in [
        (0, 3),
        (0, 4),
        (1, 3),
        (1, 5),
        (1, 0x81),
        (1, 4),
        (2, 39),
        (2, 45),
        (6, 21),
        (8, 6),
        (4, 0),
    ] {
        let mut header = tcp4_header;
        header[field] = value;
        if field == 4 {
            header[5] = 0;
        }
        assert!(
            vnet_meta(&header, &tcp4).is_none(),
            "field {field} value {value}"
        );
    }
    let mut tcp6 = vec![0; 64];
    tcp6[..8].copy_from_slice(&[0x60, 0, 0, 0, 0, 24, 6, 64]);
    tcp6[8..24].copy_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    tcp6[24..40].copy_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    tcp6[40..].copy_from_slice(&tcp4[20..]);
    let tcp6_header = [1, 4, 60, 0, 0xb4, 5, 40, 0, 16, 0];
    assert_eq!(
        vnet_meta(&tcp6_header, &tcp6),
        Some(RxMeta {
            csum: Csum::Partial {
                start: 40,
                offset: 16
            },
            gso: expected.gso,
        })
    );
    let udp4 = [
        0x45, 0, 0, 32, 0, 0, 0x40, 0, 64, 17, 0x4e, 0x97, 192, 0, 2, 1, 198, 51, 100, 1, 0xa0,
        0x28, 1, 0xbb, 0, 12, 0, 0, 1, 2, 3, 4,
    ];
    let udp_header = [1, 0, 0, 0, 0, 0, 20, 0, 6, 0];
    let record = [udp_header.as_slice(), &udp4].concat();
    let (packet, meta) = decode_record(&record).unwrap();
    assert_eq!(packet, udp4);
    assert_eq!(
        meta,
        RxMeta {
            csum: Csum::Partial {
                start: 20,
                offset: 6
            },
            gso: None
        }
    );
    let mut udp6 = tcp6[..40].to_vec();
    udp6[5] = 12;
    udp6[6] = 17;
    udp6.extend_from_slice(&udp4[20..]);
    assert_eq!(
        vnet_meta(&[1, 0, 0, 0, 0, 0, 40, 0, 6, 0], &udp6),
        Some(RxMeta {
            csum: Csum::Partial {
                start: 40,
                offset: 6
            },
            gso: None
        })
    );
    for flags in [0, 2] {
        let mut header = [0; VNET_BYTES];
        header[0] = flags;
        assert_eq!(
            vnet_meta(&header, &udp4).unwrap().csum,
            if flags == 0 {
                Csum::Verify
            } else {
                Csum::Valid
            }
        );
    }
    for length in 0..record.len() {
        assert!(decode_record(&record[..length]).is_none());
    }
    let mut padded = record;
    padded.push(0);
    assert!(decode_record(&padded).is_none());
    let mut maximum = vec![0; RX_BYTES - 1];
    maximum[VNET_BYTES] = 0x60;
    maximum[VNET_BYTES + 4..VNET_BYTES + 6].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(decode_record(&maximum).unwrap().0.len(), 65_575);
    maximum.push(0);
    assert!(decode_record(&maximum).is_none());
    assert_eq!(RX_BYTES, 65_586);
}

#[test]
fn runtime_refuses_unavailable_tun_authority_without_restricting_dial_modes() {
    let base = honk_config::parser::parse_dae_config(
        r#"
        global { nfqueue_enable: false }
        datapath {
            backend: tun
            direct: endpoint
            tun {
                name: honk0
                address4: 198.18.0.1/32
                table: 202
                rule_priority: 10000
                capture { 0.0.0.0/0 }
            }
        }
        routing { fallback: direct }
    "#,
    )
    .unwrap();
    for mode in ["ip", "domain", "domain+", "domain++"] {
        let mut config = base.clone();
        config.global.dial_mode = mode.into();
        validate_runtime(&config, false).unwrap();
    }
    assert!(validate_runtime(&base, true).is_err());
    let mut config = base.clone();
    config.global.nfqueue_enable = true;
    assert!(validate_config(&config).is_err());
    let mut config = base.clone();
    config.global.lan_interface.push("lan0".into());
    assert!(validate_config(&config).is_err());
    let mut config = base.clone();
    config.global.wan_interface.push("wan0".into());
    assert!(validate_config(&config).is_err());
    let mut config = base.clone();
    config.routing.default_mark = Some(1);
    assert!(validate_config(&config).is_err());
    for predicate in [
        "pname(curl)",
        "!pname(curl)",
        "mac(02:00:00:00:00:01)",
        "!mac(02:00:00:00:00:01)",
    ] {
        let routing = honk_config::parser::parse_dae_config(&format!(
            "routing {{\n {predicate} -> direct\n fallback: direct\n }}"
        ))
        .unwrap()
        .routing;
        let mut config = base.clone();
        config.routing = routing;
        assert!(
            validate_config(&config).is_err(),
            "accepted unavailable {predicate}"
        );
        config
            .datapath
            .as_mut()
            .unwrap()
            .tun
            .as_mut()
            .unwrap()
            .host_facts = true;
        assert_eq!(
            validate_config(&config).is_ok(),
            cfg!(feature = "ebpf") && predicate.contains("pname"),
            "Host process admission or MAC refusal changed: {predicate}"
        );
    }
    validate_runtime(&Config::default(), true).unwrap();
}

#[tokio::test]
async fn scope_class_groups_share_one_write_attempt_budget_and_keep_later_leases() {
    let (scope, owner, budget) = scope();
    let mut groups: [[Option<OutputLease>; BATCH]; 4] =
        std::array::from_fn(|_| std::array::from_fn(|_| None));
    for pending in &mut groups {
        pending[0] = Some(output(&scope).await);
    }
    let pointers: Vec<_> = groups
        .iter()
        .map(|pending| pending[0].as_ref().unwrap().packet().as_ptr())
        .collect();
    let mut attempts = 0;
    let mut bytes = 0;
    // Isolate the syscall ceiling from scheduler latency in this unit fixture.
    let started = Instant::now() + Duration::from_secs(60);
    let mut calls = 0;
    assert_eq!(
        flush_pending(
            Framing::Vnet,
            &mut groups[0],
            &mut attempts,
            &mut bytes,
            started,
            |header, packet| {
                calls += 1;
                if calls < BATCH * 2 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(header.len() + packet.len())
                }
            }
        )
        .unwrap(),
        (false, false)
    );
    assert_eq!(attempts, BATCH * 2);
    for group in 1..4 {
        assert_eq!(
            flush_pending(
                Framing::Vnet,
                &mut groups[group],
                &mut attempts,
                &mut bytes,
                started,
                |_, _| panic!("later group acquired a fresh syscall budget")
            )
            .unwrap(),
            (false, true)
        );
        assert_eq!(
            groups[group][0].as_ref().unwrap().packet().as_ptr(),
            pointers[group]
        );
    }
    // The next turn starts with the next group, without copying or replacing its lease.
    attempts = 0;
    bytes = 0;
    for group in 1..4 {
        flush_pending(
            Framing::Vnet,
            &mut groups[group],
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |header, packet| {
                assert_eq!(packet.as_ptr(), pointers[group]);
                Ok(header.len() + packet.len())
            },
        )
        .unwrap();
    }
    assert!(groups.iter().flatten().all(Option::is_none));
    scope.shutdown(true);
    owner.run().await;
    drop((groups, scope));
    assert_eq!(budget.used(), 0);
}

const ADOPTED_CONFIG: &str = r#"
    global { nfqueue_enable: false }
    datapath {
        backend: tun
        direct: endpoint
        tun {
            name: tun0
            address4: 198.18.0.1/32
            table: 202
            rule_priority: 10000
            capture { 0.0.0.0/0 }
        }
    }
    routing { fallback: direct }
"#;

#[test]
fn an_adopted_tun_is_protected_instead_of_marked_and_has_no_host_source() {
    const NAME: &str =
        "tun::tests::an_adopted_tun_is_protected_instead_of_marked_and_has_no_host_source";
    if crate::test_support::run_exact_in_child("HONK_TUN_ADOPTED_TEST_CHILD", NAME) {
        return;
    }
    let base = honk_config::parser::parse_dae_config(ADOPTED_CONFIG).unwrap();
    let error = validate_adopted(&base).unwrap_err().to_string();
    assert!(error.contains("socket protector"), "{error}");
    let _guard =
        honk_outbound::util::install_socket_protector(std::sync::Arc::new(|_| Ok(()))).unwrap();
    validate_adopted(&base).unwrap();
    let mut config = base.clone();
    config
        .datapath
        .as_mut()
        .unwrap()
        .tun
        .as_mut()
        .unwrap()
        .host_facts = true;
    assert!(validate_adopted(&config).is_err());
    let mut config = base.clone();
    config.datapath = None;
    assert!(validate_adopted(&config).is_err());
    let mut config = base;
    config.routing.default_mark = Some(1);
    assert!(validate_adopted(&config).is_err());
}

#[tokio::test]
async fn plain_records_are_bare_ip_packets_without_offload() {
    let mut ipv4 = vec![0; 28];
    ipv4[0] = 0x45;
    ipv4[2..4].copy_from_slice(&28u16.to_be_bytes());
    ipv4[9] = 17;
    let (packet, meta) = Framing::Plain.decode(&ipv4).unwrap();
    assert_eq!(packet, &ipv4[..]);
    assert_eq!(
        meta,
        RxMeta {
            csum: Csum::Verify,
            gso: None
        }
    );
    assert!(Framing::Plain.decode(&ipv4[..27]).is_none());
    let mut record = vec![0; VNET_BYTES];
    record.extend_from_slice(&ipv4);
    assert!(Framing::Plain.decode(&record).is_none());
    assert_eq!(Framing::Vnet.decode(&record).unwrap().0, &ipv4[..]);
    assert_eq!(Framing::Plain.tx_caps(), TxCaps::NONE);

    let (scope, owner, budget) = scope();
    let mut pending = std::array::from_fn(|_| None);
    pending[0] = Some(output(&scope).await);
    let expected = pending[0].as_ref().unwrap().packet().to_vec();
    let (writer, reader) = UnixDatagram::pair().unwrap();
    let mut attempts = 0;
    let mut bytes = 0;
    assert_eq!(
        flush_pending(
            Framing::Plain,
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |header, packet| {
                assert!(header.is_empty());
                write_packet(writer.as_raw_fd(), header, packet)
            },
        )
        .unwrap(),
        (false, false)
    );
    assert_eq!(bytes, expected.len());
    let mut received = vec![0; RX_BYTES];
    let length = reader.recv(&mut received).unwrap();
    assert_eq!(&received[..length], &expected[..]);
    assert!(pending[0].is_none());
    drop(pending);
    scope.shutdown(true);
    owner.run().await;
    drop(scope);
    assert_eq!(budget.used(), 0);
}

/// What an Android `VpnService` hands over: an already configured TUN that
/// carries plain IP packets. honk's direct egress is protected by the hook,
/// which marks it so the peer's local address is reached directly; every other
/// socket reaches that address through the TUN.
#[test]
#[ignore = "requires the disposable kernel VM gate"]
fn kernel_adopted_tun_carries_tcp_and_udp_through_protected_egress() {
    let expected = std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap_or_default();
    assert!(std::env::var_os("HONK_CI_VM_LANE").is_some() && !expected.is_empty());
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap()
            .trim(),
        expected
    );
    std::thread::spawn(adopted_tun_in_private_namespace)
        .join()
        .unwrap();
}

fn adopted_tun_in_private_namespace() {
    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::sync::atomic::AtomicUsize;

    const MARK: u32 = 0x77;
    let ip = |args: &str| {
        let status = std::process::Command::new("ip")
            .args(args.split_ascii_whitespace())
            .status()
            .unwrap();
        assert!(status.success(), "ip {args}: {status}");
    };
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", b"0").unwrap();
    std::fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", b"1").unwrap();
    ip("link set lo up");
    let tun: OwnedFd = nix::fcntl::open(
        "/dev/net/tun",
        nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .unwrap();
    let mut request = super::device::interface_request("tun0").unwrap();
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: TUNSETIFF reads and updates only this live, initialized ifreq.
    assert_eq!(
        unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &mut request) },
        0
    );
    ip("addr add 10.7.0.1/24 dev tun0");
    ip("link set tun0 up");
    ip("addr add 203.0.113.1/32 dev lo");
    ip(&format!("rule add pref 100 fwmark {MARK:#x} lookup local"));
    ip("rule add pref 200 lookup 100");
    ip("rule add pref 300 lookup local");
    ip("rule del pref 0");
    ip("route add 203.0.113.0/24 dev tun0 table 100");

    let bind = |kind, port| {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, kind, None).unwrap();
        socket.set_mark(MARK).unwrap();
        socket
            .bind(&std::net::SocketAddr::from(([203, 0, 113, 1], port)).into())
            .unwrap();
        socket
    };
    let listener = bind(socket2::Type::STREAM, 7000);
    listener.listen(4).unwrap();
    let listener: std::net::TcpListener = listener.into();
    let (peer_tx, peer_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, peer) = listener.accept().unwrap();
        peer_tx.send(peer).unwrap();
        let mut buffer = [0; 64];
        let length = stream.read(&mut buffer).unwrap();
        stream.write_all(&buffer[..length]).unwrap();
    });
    let health = bind(socket2::Type::STREAM, 7002);
    health.listen(4).unwrap();
    let udp: std::net::UdpSocket = bind(socket2::Type::DGRAM, 7001).into();
    std::thread::spawn(move || {
        let mut buffer = [0; 64];
        let (length, peer) = udp.recv_from(&mut buffer).unwrap();
        udp.send_to(&buffer[..length], peer).unwrap();
    });

    let protected = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&protected);
    let _guard = honk_outbound::util::install_socket_protector(Arc::new(move |fd| {
        socket2::SockRef::from(&fd).set_mark(MARK)?;
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }))
    .unwrap();
    let mut config = honk_config::parser::parse_dae_config(
        &ADOPTED_CONFIG.replace("198.18.0.1/32", "10.7.0.1/32"),
    )
    .unwrap();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        // Built as the daemon builds it: the userspace backend and a running
        // datapath flags writer, which the capture needs before readiness.
        config.validate_assembled().unwrap();
        let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
        let forwarder = resolver.forwarder();
        let admission = Arc::new(AtomicBool::new(false));
        let pname = Arc::new(parking_lot::RwLock::new(
            crate::ebpf::PnameSupport::Unavailable,
        ));
        let mut plane = ControlPlane::new(
            config.clone(),
            Box::new(crate::ebpf::userspace::UserspaceBackend::new(
                Arc::clone(&admission),
                Arc::clone(&pname),
            )),
            crate::routing::Router::from_config(&config.routing).unwrap(),
            Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver().unwrap()),
            resolver,
            forwarder,
        )
        .unwrap();
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Rule", "direct"),
        )));
        plane.start_datapath_flags_coordinator().unwrap();
        plane
            .alive_set()
            .set_direct_check_addr("203.0.113.1:7002".into());
        let shutdown = plane.shutdown_intent();
        let tracker = plane.connection_tracker();
        tracker.enable();
        let running = tokio::spawn(run_adopted_tun(plane, tun, Arc::clone(&admission), pname));
        tokio::time::timeout(Duration::from_secs(20), async {
            while !admission.load(Ordering::Acquire) {
                assert!(
                    !running.is_finished(),
                    "adopted TUN stopped before readiness"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("adopted TUN capture must become ready");

        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect("203.0.113.1:7000"),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stream.local_addr().unwrap().ip().to_string(), "10.7.0.1");
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"through-tcp")
            .await
            .unwrap();
        let mut echoed = [0; 11];
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&echoed, b"through-tcp");
        // netstack terminated the client's connection and honk dialed its own:
        // the server sees honk's egress socket, and the plane tracks the flow.
        let client = stream.local_addr().unwrap();
        assert_ne!(peer_rx.recv().unwrap(), client);
        assert!(
            tracker.snapshot().iter().any(|flow| flow.network == "tcp"
                && flow.source == client.to_string()
                && flow.destination == "203.0.113.1:7000"),
            "{:?}",
            tracker
                .snapshot()
                .iter()
                .map(|flow| (&flow.network, &flow.source, &flow.destination))
                .collect::<Vec<_>>()
        );

        let client = tokio::net::UdpSocket::bind("10.7.0.1:0").await.unwrap();
        client
            .send_to(b"through-udp", "203.0.113.1:7001")
            .await
            .unwrap();
        let mut echoed = [0; 64];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut echoed))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&echoed[..length], b"through-udp");
        assert_eq!(peer.to_string(), "203.0.113.1:7001");
        assert!(
            protected.load(Ordering::SeqCst) >= 2,
            "both direct dials were protected"
        );

        shutdown.request();
        let (_, result) = tokio::time::timeout(Duration::from_secs(20), running)
            .await
            .unwrap()
            .unwrap();
        result.unwrap();
    });
}
