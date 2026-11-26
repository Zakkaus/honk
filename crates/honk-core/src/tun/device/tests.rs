use super::*;

#[test]
fn tun_attachment_requires_vnet_single_queue_flags_and_a_bounded_name() {
    let flags = libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR;
    assert!(valid_attachment_flags(flags));
    assert!(valid_attachment_flags(flags | libc::IFF_TUN_EXCL));
    for wrong in [
        flags | libc::IFF_MULTI_QUEUE,
        flags & !libc::IFF_VNET_HDR,
        flags | libc::IFF_NAPI,
        flags | libc::IFF_PERSIST,
        flags | libc::IFF_NAPI_FRAGS,
        flags | libc::IFF_ONE_QUEUE,
        flags | libc::IFF_NO_CARRIER,
        libc::IFF_TUN,
        libc::IFF_TAP | libc::IFF_NO_PI,
    ] {
        assert!(!valid_attachment_flags(wrong));
    }
    for name in ["", "abcdefghijklmnop", "honk\0other"] {
        assert!(interface_request(name).is_err());
    }
    let request = interface_request("abcdefghijklmno").unwrap();
    assert_eq!(request.ifr_name[15], 0);
}

#[test]
fn vnet_setup_refuses_an_unsupported_descriptor_without_fallback() {
    let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let error = configure_vnet(socket.as_raw_fd()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}
