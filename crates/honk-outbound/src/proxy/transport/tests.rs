use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn transport_node(port: u16) -> Node {
    Node {
        name: "transport-node".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
        ..Default::default()
    }
}

/// An inner stream that yields at most one byte per poll_read and
/// accepts at most one byte per poll_write — the short-IO regression
/// case for gRPC framing.
#[derive(Debug)]
struct DribbleStream {
    reader: std::collections::VecDeque<u8>,
    written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for DribbleStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(b) = self.reader.pop_front() {
            buf.put_slice(&[b]);
        }
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for DribbleStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.written.lock().unwrap().push(buf[0]);
        Poll::Ready(Ok(1))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
struct GatedWriter {
    open: std::sync::Arc<std::sync::atomic::AtomicBool>,
    written: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
    write_zero: bool,
}

impl tokio::io::AsyncRead for GatedWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for GatedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_zero {
            return Poll::Ready(Ok(0));
        }
        if !self.open.load(std::sync::atomic::Ordering::Acquire) {
            return Poll::Pending;
        }
        self.written.lock().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn grpc_queued_write_owns_caller_bytes_and_zero_write_errors() {
    let open = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let written = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let mut stream = GrpcStream {
        inner: Box::new(GatedWriter {
            open: open.clone(),
            written: written.clone(),
            write_zero: false,
        }),
        stream_id: 1,
        read_buf: Vec::new(),
        undecoded: Vec::new(),
        msg_buf: Vec::new(),
        write_queue: VecDeque::new(),
        send_stream_window: H2_DEFAULT_WINDOW,
        send_conn_window: H2_DEFAULT_WINDOW,
        peer_initial_window: H2_DEFAULT_WINDOW,
        peer_max_frame: H2_DEFAULT_MAX_FRAME,
        recv_unacked: 0,
        control_pending: false,
        stream_eof: false,
        end_stream_sent: false,
        data_seen: false,
        header_block: Vec::new(),
        header_end_stream: false,
        failure: None,
    };

    let mut owned = b"owned".to_vec();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), stream.write(&owned))
            .await
            .expect("queue ownership must not wait for the blocked writer")
            .unwrap(),
        owned.len()
    );
    owned.fill(b'z');
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            stream.write(b"cancelled"),
        )
        .await
        .is_err()
    );
    open.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(stream.write(b"x").await.unwrap(), 1);
    stream.flush().await.unwrap();

    let mut expected = Vec::new();
    push_frame_header(&mut expected, 12, H2_DATA, 0, 1);
    expected.extend_from_slice(&[0, 0, 0, 0, 7, 0x0a, 5]);
    expected.extend_from_slice(b"owned");
    push_frame_header(&mut expected, 8, H2_DATA, 0, 1);
    expected.extend_from_slice(&[0, 0, 0, 0, 3, 0x0a, 1, b'x']);
    assert_eq!(*written.lock(), expected);

    let mut zero = GrpcStream {
        inner: Box::new(GatedWriter {
            open,
            written: Default::default(),
            write_zero: true,
        }),
        stream_id: 1,
        read_buf: Vec::new(),
        undecoded: Vec::new(),
        msg_buf: Vec::new(),
        write_queue: b"queued".to_vec().into(),
        send_stream_window: H2_DEFAULT_WINDOW,
        send_conn_window: H2_DEFAULT_WINDOW,
        peer_initial_window: H2_DEFAULT_WINDOW,
        peer_max_frame: H2_DEFAULT_MAX_FRAME,
        recv_unacked: 0,
        control_pending: false,
        stream_eof: false,
        end_stream_sent: false,
        data_seen: false,
        header_block: Vec::new(),
        header_end_stream: false,
        failure: None,
    };
    let error = tokio::time::timeout(std::time::Duration::from_millis(20), zero.flush())
        .await
        .expect("zero-byte write must terminate")
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
}

#[tokio::test]
async fn grpc_partial_control_writes_reclaim_consumed_storage() {
    let (client, mut server) = tokio::io::duplex(13);
    let mut stream = GrpcStream {
        inner: Box::new(client),
        stream_id: 1,
        read_buf: Vec::new(),
        undecoded: Vec::new(),
        msg_buf: Vec::new(),
        write_queue: VecDeque::new(),
        send_stream_window: H2_DEFAULT_WINDOW,
        send_conn_window: H2_DEFAULT_WINDOW,
        peer_initial_window: H2_DEFAULT_WINDOW,
        peer_max_frame: H2_DEFAULT_MAX_FRAME,
        recv_unacked: 0,
        control_pending: false,
        stream_eof: false,
        end_stream_sent: false,
        data_seen: false,
        header_block: Vec::new(),
        header_end_stream: false,
        failure: None,
    };
    assert_eq!(stream.write(b"seed").await.unwrap(), 4);
    let mut expected = vec![0, 0, 11, H2_DATA, 0, 0, 0, 0, 1, 0, 0, 0, 0, 6, 0x0a, 4];
    expected.extend_from_slice(b"seed");
    let mut received = Vec::new();
    let mut partial = [0; 13];
    assert!(futures_util::poll!(std::pin::pin!(stream.flush())).is_pending());
    server.read_exact(&mut partial).await.unwrap();
    received.extend_from_slice(&partial);

    // Keep seven bytes unsent throughout; only the live frame backlog,
    // not lifetime wire traffic, may determine retained queue storage.
    for increment in 1u32..=8 {
        stream.recv_unacked = increment;
        stream.queue_window_updates();
        for stream_id in [1, 0] {
            expected.extend_from_slice(&[0, 0, 4, H2_WINDOW_UPDATE, 0, 0, 0, 0, stream_id]);
            expected.extend_from_slice(&increment.to_be_bytes());
        }
        for _ in 0..2 {
            assert!(futures_util::poll!(std::pin::pin!(stream.flush())).is_pending());
            server.read_exact(&mut partial).await.unwrap();
            received.extend_from_slice(&partial);
        }
        assert_eq!(received, expected[..expected.len() - 7]);
        assert!(stream.write_queue.capacity() <= 4 * 26);
    }

    stream.flush().await.unwrap();
    let mut remaining = [0; 7];
    server.read_exact(&mut remaining).await.unwrap();
    received.extend_from_slice(&remaining);
    assert_eq!(received, expected);
}

#[tokio::test]
async fn test_grpc_stream_tolerates_short_reads_and_writes() {
    // One gRPC DATA frame on stream 1: [9B h2 hdr][5B length prefix]
    // [protobuf envelope: 0a <len> "pong"].
    let mut wire = Vec::new();
    wire.extend_from_slice(&[0, 0, 11, H2_DATA, 0, 0, 0, 0, 1]);
    wire.extend_from_slice(&[0, 0, 0, 0, 6, 0x0a, 0x04]);
    wire.extend_from_slice(b"pong");
    let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let inner = DribbleStream {
        reader: wire.into(),
        written: written.clone(),
    };
    let mut stream = GrpcStream {
        inner: Box::new(inner),
        stream_id: 1,
        read_buf: Vec::new(),
        undecoded: Vec::new(),
        msg_buf: Vec::new(),
        write_queue: VecDeque::new(),
        send_stream_window: H2_DEFAULT_WINDOW,
        send_conn_window: H2_DEFAULT_WINDOW,
        peer_initial_window: H2_DEFAULT_WINDOW,
        peer_max_frame: H2_DEFAULT_MAX_FRAME,
        recv_unacked: 0,
        control_pending: false,
        stream_eof: false,
        end_stream_sent: false,
        data_seen: false,
        header_block: Vec::new(),
        header_end_stream: false,
        failure: None,
    };

    // Read: the frame arrives one byte at a time but must decode whole.
    let mut out = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut out)
        .await
        .unwrap();
    assert_eq!(&out, b"pong");

    // Write: the frame leaves one byte at a time but must be complete.
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"ping")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();
    let got = written.lock().unwrap().clone();
    let mut want = Vec::new();
    want.extend_from_slice(&[0, 0, 11, H2_DATA, 0, 0, 0, 0, 1]);
    want.extend_from_slice(&[0, 0, 0, 0, 6, 0x0a, 0x04]);
    want.extend_from_slice(b"ping");
    assert_eq!(got, want);
}

/// WebSocket transport: the mock server verifies the upgrade request
/// (path + Host header) and echoes one binary message.
// The accept callback's Result type (and its large Err variant) is
// dictated by tungstenite's `Callback` trait.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn test_ws_transport_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        use futures_util::{SinkExt, StreamExt};
        let (stream, _) = listener.accept().await.unwrap();
        let mut seen_tx = Some(seen_tx);
        let callback =
            |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
             resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(tx) = seen_tx.take() {
                    let _ = tx.send((req.uri().path().to_string(), host));
                }
                Ok(resp)
            };
        let mut ws = tokio_tungstenite::accept_hdr_async(stream, callback)
            .await
            .unwrap();
        let msg = ws.next().await.unwrap().unwrap();
        assert_eq!(&msg.into_data()[..], b"ping");
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            b"pong".to_vec().into(),
        ))
        .await
        .unwrap();
    });

    let mut node = transport_node(port);
    let transport = node.transport_mut().unwrap();
    transport.transport = "ws".into();
    transport.ws_path = Some("/ws-path".into());
    transport.ws_host = Some("cdn.example.com".into());

    let mut stream = wrap_transport(&node, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buf, b"pong");

    let (path, host) = seen_rx.await.unwrap();
    assert_eq!(path, "/ws-path");
    assert_eq!(host.as_deref(), Some("cdn.example.com"));

    server.await.unwrap();
}

#[allow(clippy::result_large_err)]
#[tokio::test]
async fn vmess_json_empty_ws_host_uses_endpoint_in_handshake() {
    use base64::Engine as _;

    let payload = r#"{
            "add": "example.invalid",
            "port": 443,
            "id": "00000000-0000-0000-0000-000000000001",
            "net": "ws",
            "host": "",
            "path": "/ws"
        }"#;
    let link = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(payload),
    );
    let node = Node::from_share_link(&link).unwrap();
    let (client, server) = tokio::io::duplex(4096);
    let receive = async {
        let mut host = None;
        let callback =
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
             response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                host = request.headers().get("host").cloned();
                Ok(response)
            };
        let _connection = tokio_tungstenite::accept_hdr_async(server, callback)
            .await
            .unwrap();
        host.unwrap()
    };
    let (stream, host) = tokio::join!(wrap_ws(&node, Box::new(client)), receive);
    let _stream = stream.unwrap();
    assert_eq!(host, "example.invalid");
}

async fn decoded_grpc_headers(service_len: usize, authority: &str) -> (String, String) {
    let mut node = transport_node(443);
    node.host = authority.to_owned();
    node.transport_mut().unwrap().grpc_service = Some("s".repeat(service_len));
    let (client, server) = tokio::io::duplex(4096);
    let receive = async {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let request = connection.accept().await.expect("gRPC request");
        assert!(request.is_ok(), "invalid gRPC headers: {request:?}");
        let (request, _) = request.unwrap();
        assert_eq!(request.headers()["content-type"], "application/grpc");
        assert_eq!(request.headers()["te"], "trailers");
        assert_eq!(request.headers()["user-agent"], "honk");
        (
            request.uri().path().to_owned(),
            request.uri().authority().unwrap().as_str().to_owned(),
        )
    };
    let (stream, headers) = tokio::join!(wrap_grpc(&node, Box::new(client)), receive);
    stream.unwrap();
    headers
}

#[tokio::test]
async fn test_grpc_hpack_path_length_200() {
    let (path, _) = decoded_grpc_headers(195, "example.com").await;
    assert_eq!(path.len(), 200);
    assert_eq!(path, format!("/{}/Tun", "s".repeat(195)));
}

#[tokio::test]
async fn test_grpc_hpack_path_length_127_boundary() {
    let (path, _) = decoded_grpc_headers(122, "example.com").await;
    assert_eq!(path.len(), 127);
    assert_eq!(path, format!("/{}/Tun", "s".repeat(122)));
}

#[tokio::test]
async fn test_grpc_hpack_authority_length_300() {
    let authority = "a".repeat(300);
    let (_, decoded) = decoded_grpc_headers(1, &authority).await;
    assert_eq!(decoded, authority);
}

/// gRPC transport: the mock server verifies the HTTP/2 preface, the
/// client SETTINGS frame, the HEADERS frame (path, content-type,
/// authority) and the DATA+gRPC-LP framing in both directions.
#[tokio::test]
async fn test_grpc_transport_roundtrip() {
    const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // HTTP/2 connection preface.
        let mut preface = [0u8; 24];
        stream.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, H2_PREFACE);

        // Client SETTINGS frame: INITIAL_WINDOW_SIZE = 2^31 - 1.
        let (len, ty, sid) = read_h2_header(&mut stream).await;
        assert_eq!((len, ty, sid), (6, H2_SETTINGS, 0));
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload[..2], &[0, 4]);
        assert_eq!(
            u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]),
            0x7FFF_FFFF
        );

        // Connection-level WINDOW_UPDATE: 65535 + inc = 2^31 - 1.
        let (len, ty, sid) = read_h2_header(&mut stream).await;
        assert_eq!((len, ty, sid), (4, H2_WINDOW_UPDATE, 0));
        let mut payload = vec![0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
            0x7FFF_FFFF - 65535
        );

        // HEADERS frame opening stream 1.
        let (len, ty, sid) = read_h2_header(&mut stream).await;
        assert_eq!(ty, H2_HEADERS);
        assert_eq!(sid, 1);
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await.unwrap();
        let payload = String::from_utf8_lossy(&payload);
        assert!(payload.contains("/testSvc/Tun"));
        assert!(payload.contains("application/grpc"));
        assert!(payload.contains("127.0.0.1"));

        // DATA frame carrying one gRPC message "hello".
        let (len, ty, sid) = read_h2_header(&mut stream).await;
        assert_eq!(ty, H2_DATA);
        assert_eq!(sid, 1);
        assert_eq!(len, 5 + 7);
        let mut frame = vec![0u8; len as usize];
        stream.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame[0], 0x00); // uncompressed
        assert_eq!(&frame[1..5], &[0, 0, 0, 7]);
        assert_eq!(&frame[5..7], &[0x0a, 0x05]); // protobuf bytes field
        assert_eq!(&frame[7..], b"hello");

        // Reply with one DATA frame carrying a gRPC message "world",
        // coalesced into a single write so the client's single-poll
        // reads observe complete frames.
        let h2_len: u32 = 5 + 7;
        let mut reply = Vec::new();
        reply.extend_from_slice(&[
            (h2_len >> 16) as u8,
            (h2_len >> 8) as u8,
            h2_len as u8,
            H2_DATA,
            0x00,
            0,
            0,
            0,
            1,
        ]);
        reply.push(0x00); // uncompressed
        reply.extend_from_slice(&7u32.to_be_bytes());
        reply.extend_from_slice(&[0x0a, 0x05]);
        reply.extend_from_slice(b"world");
        stream.write_all(&reply).await.unwrap();
    });

    let mut node = transport_node(port);
    let transport = node.transport_mut().unwrap();
    transport.transport = "grpc".into();
    transport.grpc_service = Some("testSvc".into());

    let mut stream = wrap_transport(&node, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buf, b"world");

    server.await.unwrap();
}

/// gRPC flow control: SETTINGS_INITIAL_WINDOW_SIZE applies to the already
/// open stream. A zero window stalls DATA, while a legal 128-byte window
/// accepts the largest application chunk whose exact envelope fits. The
/// shutdown path then emits an empty END_STREAM DATA frame.
#[tokio::test]
async fn test_grpc_transport_small_send_window_and_end_stream() {
    let (client_side, mut server_side) = tokio::io::duplex(8192);
    let mut stream = GrpcStream {
        inner: Box::new(client_side),
        stream_id: 1,
        read_buf: Vec::new(),
        undecoded: Vec::new(),
        msg_buf: Vec::new(),
        write_queue: VecDeque::new(),
        send_stream_window: H2_DEFAULT_WINDOW,
        send_conn_window: H2_DEFAULT_WINDOW,
        peer_initial_window: H2_DEFAULT_WINDOW,
        peer_max_frame: H2_DEFAULT_MAX_FRAME,
        recv_unacked: 0,
        control_pending: false,
        stream_eof: false,
        end_stream_sent: false,
        data_seen: false,
        header_block: Vec::new(),
        header_end_stream: false,
        failure: None,
    };

    // Shrink the open stream's send window to zero.
    let mut settings = Vec::new();
    push_frame_header(&mut settings, 6, H2_SETTINGS, 0, 0);
    settings.extend_from_slice(&[0, 4]);
    settings.extend_from_slice(&0u32.to_be_bytes());
    server_side.write_all(&settings).await.unwrap();

    // Drive one read so the client processes the SETTINGS before the
    // write attempt (frame parsing is read-driven by design).
    let mut sink = [0u8; 16];
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        stream.read(&mut sink),
    )
    .await;

    // The write must stall while the window is zero.
    let stalled = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stream.write_all(b"hello"),
    )
    .await;
    assert!(stalled.is_err(), "client wrote with a zero window");

    // A legal small initial window must make progress without waiting for
    // an arbitrary minimum frame size.
    let mut setting = Vec::new();
    push_frame_header(&mut setting, 6, H2_SETTINGS, 0, 0);
    setting.extend_from_slice(&[0, 4]);
    setting.extend_from_slice(&128u32.to_be_bytes());
    server_side.write_all(&setting).await.unwrap();
    let payload = [0x5a; 256];
    let accepted = tokio::time::timeout(std::time::Duration::from_secs(2), stream.write(&payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted, 121);
    stream.flush().await.unwrap();

    // Wire order: one ACK per SETTINGS, then the exactly bounded DATA frame.
    let mut got = vec![0u8; 9 + 9 + 9 + 128];
    server_side.read_exact(&mut got).await.unwrap();
    let ack = [0, 0, 0, H2_SETTINGS, H2_FLAG_ACK, 0, 0, 0, 0];
    assert_eq!(&got[..9], &ack);
    assert_eq!(&got[9..18], &ack);
    let data = &got[18..];
    assert_eq!(&data[..9], &[0, 0, 128, H2_DATA, 0, 0, 0, 0, 1]);
    assert_eq!(&data[9..16], &[0, 0, 0, 0, 123, 0x0a, 121]);
    assert_eq!(&data[16..], &payload[..accepted]);

    let mut grant = Vec::new();
    push_frame_header(&mut grant, 4, H2_WINDOW_UPDATE, 0, 1);
    grant.extend_from_slice(&136u32.to_be_bytes());
    server_side.write_all(&grant).await.unwrap();
    let accepted = stream.write(&payload).await.unwrap();
    assert_eq!(accepted, 128);
    stream.flush().await.unwrap();

    let mut data = vec![0; 9 + 136];
    server_side.read_exact(&mut data).await.unwrap();
    assert_eq!(&data[..9], &[0, 0, 136, H2_DATA, 0, 0, 0, 0, 1]);
    assert_eq!(&data[9..17], &[0, 0, 0, 0, 131, 0x0a, 0x80, 0x01]);
    assert_eq!(&data[17..], &payload[..accepted]);

    // poll_shutdown queues an empty DATA frame with END_STREAM.
    tokio::time::timeout(std::time::Duration::from_secs(2), stream.shutdown())
        .await
        .unwrap()
        .unwrap();
    let mut end = [0u8; 9];
    server_side.read_exact(&mut end).await.unwrap();
    assert_eq!(&end, &[0, 0, 0, H2_DATA, H2_FLAG_END_STREAM, 0, 0, 0, 1]);

    // Even a fresh window grant cannot reopen the closed write side.
    server_side.write_all(&grant).await.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), stream.write(b"x"))
        .await
        .expect("closed write must not wait for flow control")
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(stream.write(&[]).await.unwrap(), 0);
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(server_side.read(&mut end).await.unwrap(), 0);
}

/// gRPC read side: the read window is topped up once the received DATA
/// crosses H2_WINDOW_REFRESH, as one stream-level and one
/// connection-level WINDOW_UPDATE.
#[tokio::test]
async fn test_grpc_transport_window_refresh() {
    let mut stream = GrpcStream {
        inner: Box::new(DribbleStream {
            reader: Default::default(),
            written: Default::default(),
        }),
        stream_id: 1,
        read_buf: Vec::new(),
        undecoded: Vec::new(),
        msg_buf: Vec::new(),
        write_queue: VecDeque::new(),
        send_stream_window: H2_DEFAULT_WINDOW,
        send_conn_window: H2_DEFAULT_WINDOW,
        peer_initial_window: H2_DEFAULT_WINDOW,
        peer_max_frame: H2_DEFAULT_MAX_FRAME,
        recv_unacked: 0,
        control_pending: false,
        stream_eof: false,
        end_stream_sent: false,
        data_seen: false,
        header_block: Vec::new(),
        header_end_stream: false,
        failure: None,
    };
    let data_len = H2_WINDOW_REFRESH + 100;
    let mut wire = Vec::new();
    push_frame_header(&mut wire, data_len, H2_DATA, 0, 1);
    wire.extend(std::iter::repeat_n(0u8, data_len as usize));
    stream.undecoded = wire;

    assert!(stream.try_parse_frame());
    assert_eq!(stream.msg_buf.len(), data_len as usize);
    let mut expect = Vec::new();
    for sid in [1, 0] {
        push_frame_header(&mut expect, 4, H2_WINDOW_UPDATE, 0, sid);
        expect.extend_from_slice(&data_len.to_be_bytes());
    }
    assert_eq!(
        stream.write_queue, expect,
        "one WINDOW_UPDATE pair topping up the received bytes"
    );
    assert!(stream.control_pending);
}

/// Read one HTTP/2 frame header: returns (payload_len, type, stream_id).
async fn read_h2_header(stream: &mut tokio::net::TcpStream) -> (u32, u8, u32) {
    let mut hdr = [0u8; 9];
    stream.read_exact(&mut hdr).await.unwrap();
    let len = ((hdr[0] as u32) << 16) | ((hdr[1] as u32) << 8) | hdr[2] as u32;
    let ty = hdr[3];
    let sid = u32::from_be_bytes([hdr[5] & 0x7F, hdr[6], hdr[7], hdr[8]]);
    (len, ty, sid)
}

/// A gRPC stream over a scripted inner transport: the frames in `wire`
/// arrive one byte at a time, the way the short-read regression test does.
fn scripted_grpc(wire: Vec<u8>) -> GrpcStream {
    GrpcStream {
        inner: Box::new(DribbleStream {
            reader: wire.into(),
            written: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }),
        stream_id: 1,
        read_buf: Vec::new(),
        undecoded: Vec::new(),
        msg_buf: Vec::new(),
        write_queue: VecDeque::new(),
        send_stream_window: H2_DEFAULT_WINDOW,
        send_conn_window: H2_DEFAULT_WINDOW,
        peer_initial_window: H2_DEFAULT_WINDOW,
        peer_max_frame: H2_DEFAULT_MAX_FRAME,
        recv_unacked: 0,
        control_pending: false,
        stream_eof: false,
        end_stream_sent: false,
        data_seen: false,
        header_block: Vec::new(),
        header_end_stream: false,
        failure: None,
    }
}

fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    push_frame_header(
        &mut frame,
        payload.len() as u32,
        frame_type,
        flags,
        stream_id,
    );
    frame.extend_from_slice(payload);
    frame
}

/// One gRPC DATA frame carrying `content` in the gun envelope.
fn grpc_data_frame(content: &[u8]) -> Vec<u8> {
    let mut payload = vec![
        0,
        0,
        0,
        0,
        (content.len() + 2) as u8,
        0x0a,
        content.len() as u8,
    ];
    payload.extend_from_slice(content);
    h2_frame(H2_DATA, 0, 1, &payload)
}

/// An HPACK literal field (no indexing) with plain-text name and value.
fn hpack_literal(name: &str, value: &str) -> Vec<u8> {
    let mut field = vec![0x00, name.len() as u8];
    field.extend_from_slice(name.as_bytes());
    field.push(value.len() as u8);
    field.extend_from_slice(value.as_bytes());
    field
}

async fn read_all(stream: &mut GrpcStream) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(stream, &mut out)
        .await
        .map(|_| out)
}

#[tokio::test]
async fn grpc_trailers_only_response_is_a_refusal() {
    // `:status 200` (static index 8) then `grpc-status: 14`, END_STREAM, no DATA.
    let mut block = vec![0x88];
    block.extend(hpack_literal("grpc-status", "14"));
    let wire = h2_frame(
        H2_HEADERS,
        H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
        1,
        &block,
    );
    let error = read_all(&mut scripted_grpc(wire)).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("grpc-status 14"), "{error}");
}

#[tokio::test]
async fn grpc_http_error_status_is_a_refusal() {
    // `:status 404` (static index 13) with a body the client must not take as data.
    let mut wire = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, &[0x8d]);
    wire.extend(h2_frame(
        H2_DATA,
        H2_FLAG_END_STREAM,
        1,
        b"<html>not found</html>",
    ));
    let error = read_all(&mut scripted_grpc(wire)).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("HTTP 404"), "{error}");
}

#[tokio::test]
async fn grpc_reset_and_goaway_are_errors() {
    let reset = h2_frame(H2_RST_STREAM, 0, 1, &7u32.to_be_bytes());
    let error = read_all(&mut scripted_grpc(reset)).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(error.to_string().contains("error code 7"), "{error}");

    let mut goaway = 1u32.to_be_bytes().to_vec();
    goaway.extend_from_slice(&11u32.to_be_bytes());
    let error = read_all(&mut scripted_grpc(h2_frame(H2_GOAWAY, 0, 0, &goaway)))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    assert!(error.to_string().contains("error code 11"), "{error}");
}

#[tokio::test]
async fn grpc_served_stream_with_ok_trailers_reads_to_eof() {
    let mut wire = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, &[0x88]);
    wire.extend(grpc_data_frame(b"pong"));
    // Padded trailers, the header block split over a CONTINUATION frame.
    let trailers = hpack_literal("grpc-status", "0");
    let (head, tail) = trailers.split_at(4);
    let mut padded = vec![2];
    padded.extend_from_slice(head);
    padded.extend_from_slice(&[0, 0]);
    wire.extend(h2_frame(
        H2_HEADERS,
        H2_FLAG_END_STREAM | H2_FLAG_PADDED,
        1,
        &padded,
    ));
    wire.extend(h2_frame(H2_CONTINUATION, H2_FLAG_END_HEADERS, 1, tail));
    assert_eq!(read_all(&mut scripted_grpc(wire)).await.unwrap(), b"pong");
}

#[tokio::test]
async fn grpc_failed_trailers_after_data_are_an_error() {
    let mut wire = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, &[0x88]);
    wire.extend(grpc_data_frame(b"partial"));
    let block = hpack_literal("grpc-status", "13");
    wire.extend(h2_frame(
        H2_HEADERS,
        H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
        1,
        &block,
    ));
    let mut stream = scripted_grpc(wire);
    let mut first = [0u8; 7];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut first)
        .await
        .unwrap();
    assert_eq!(&first, b"partial");
    let error = read_all(&mut stream).await.unwrap_err();
    assert!(error.to_string().contains("grpc-status 13"), "{error}");
}

#[tokio::test]
async fn grpc_graceful_goaway_lets_the_admitted_stream_finish() {
    // GOAWAY(last_stream_id = 1, NO_ERROR) then the response completes.
    let mut goaway = 1u32.to_be_bytes().to_vec();
    goaway.extend_from_slice(&0u32.to_be_bytes());
    let mut wire = h2_frame(H2_GOAWAY, 0, 0, &goaway);
    wire.extend(h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, &[0x88]));
    wire.extend(grpc_data_frame(b"late"));
    wire.extend(h2_frame(
        H2_HEADERS,
        H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
        1,
        &hpack_literal("grpc-status", "0"),
    ));
    assert_eq!(read_all(&mut scripted_grpc(wire)).await.unwrap(), b"late");
    // GOAWAY that excludes our stream is a failure even with NO_ERROR.
    let mut excluded = 0u32.to_be_bytes().to_vec();
    excluded.extend_from_slice(&0u32.to_be_bytes());
    let error = read_all(&mut scripted_grpc(h2_frame(H2_GOAWAY, 0, 0, &excluded)))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn grpc_split_trailers_only_refusal_is_an_error() {
    // END_STREAM travels on the HEADERS frame; the verdict waits for CONTINUATION.
    let block = hpack_literal("grpc-status", "14");
    let (head, tail) = block.split_at(5);
    let mut wire = h2_frame(H2_HEADERS, H2_FLAG_END_STREAM, 1, head);
    wire.extend(h2_frame(H2_CONTINUATION, H2_FLAG_END_HEADERS, 1, tail));
    let error = read_all(&mut scripted_grpc(wire)).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("grpc-status 14"), "{error}");
}

/// A trailer the encoder wrote with a Huffman name and a dynamic-table reference.
#[tokio::test]
async fn grpc_huffman_and_dynamic_table_trailers_are_read() {
    let mut wire = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, &[0x88]);
    wire.extend(grpc_data_frame(b"partial"));
    // Literal with incremental indexing: Huffman "grpc-status" (RFC 7541 appendix B) = "13", then
    // an indexed reference to that new dynamic entry (index 62) in a second block.
    let mut block = vec![
        0x40, 0x88, 0x9a, 0xca, 0xc8, 0xb2, 0x12, 0x34, 0xda, 0x8f, 0x02, b'1', b'3',
    ];
    wire.extend(h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, &block));
    block = vec![0x80 | 62];
    wire.extend(h2_frame(
        H2_HEADERS,
        H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
        1,
        &block,
    ));
    let mut stream = scripted_grpc(wire);
    let mut first = [0u8; 7];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut first)
        .await
        .unwrap();
    let error = read_all(&mut stream).await.unwrap_err();
    assert!(error.to_string().contains("grpc-status 13"), "{error}");
}

/// Against a real h2 server, whose HPACK encoder uses Huffman strings and the
/// dynamic table: a stream that fails after data is an error, not EOF.
#[tokio::test]
async fn grpc_failed_trailers_from_h2_server_are_an_error() {
    let mut node = transport_node(443);
    node.transport_mut().unwrap().grpc_service = Some("svc".into());
    let (client, server) = tokio::io::duplex(4096);
    let serve = async {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let (_, mut respond) = connection.accept().await.expect("request").unwrap();
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut body = respond.send_response(response, false).unwrap();
        let mut message = vec![0, 0, 0, 0, 6, 0x0a, 0x04];
        message.extend_from_slice(b"pong");
        body.send_data(bytes::Bytes::from(message), false).unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "13".parse().unwrap());
        trailers.insert("grpc-message", "internal".parse().unwrap());
        body.send_trailers(trailers).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while connection.accept().await.is_some() {}
        })
        .await;
    };
    let read = async {
        let mut stream = wrap_grpc(&node, Box::new(client)).await.unwrap();
        let mut first = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut first)
            .await
            .unwrap();
        assert_eq!(&first, b"pong");
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut rest).await
    };
    let (result, _) = tokio::join!(read, serve);
    let error = result.expect_err("non-zero grpc-status trailers are a failure");
    assert!(error.to_string().contains("grpc-status 13"), "{error}");
}

/// Against a real h2 server, whose HPACK encoder may use Huffman strings and
/// the dynamic table: a refused stream is still an error, never a clean EOF.
#[tokio::test]
async fn grpc_refusal_from_h2_server_is_an_error() {
    let mut node = transport_node(443);
    node.transport_mut().unwrap().grpc_service = Some("svc".into());
    let (client, server) = tokio::io::duplex(4096);
    let refuse = async {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let (_, mut respond) = connection.accept().await.expect("request").unwrap();
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .header("grpc-status", "14")
            .body(())
            .unwrap();
        respond.send_response(response, true).unwrap();
        // Keep the connection alive until the client has read the refusal.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while connection.accept().await.is_some() {}
        })
        .await;
    };
    let read = async {
        let mut stream = wrap_grpc(&node, Box::new(client)).await.unwrap();
        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut out).await
    };
    let (result, _) = tokio::join!(read, refuse);
    let error = result.expect_err("a trailers-only gRPC response is a refusal");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "{error}"
    );
}
