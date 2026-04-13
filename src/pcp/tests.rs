use bytes::BytesMut;

use super::*;

#[test]
fn test_validate_base_response_too_short() {
    // Less than 24 bytes should return InvalidResponse
    let mut bb = BytesMut::from(&[0u8; 16][..]);
    let err = validate_base_response(&mut bb, OperationCode::Map).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::TooFewBytes {
            received: 16,
            expected: HEADER_SIZE
        })
    ));
}

#[test]
fn test_validate_base_response_invalid_length() {
    // More than 24 bytes but not a multiple of 4 bytes should return InvalidResponse
    let mut bb = BytesMut::from(&[0u8; 27][..]);
    let err = validate_base_response(&mut bb, OperationCode::Map).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::ResponseNotMultipleOfFour(27))
    ));
}

#[test]
fn test_validate_base_response_unsupported_version() {
    // Correct length, but version is not required PCP version 2
    let mut bb = BytesMut::with_capacity(HEADER_SIZE);
    bb.put_u8(0xFF); // version (invalid)
    bb.put_bytes(0u8, 23); // rest of header unchecked
    let err = validate_base_response(&mut bb, OperationCode::Map).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::UnknownVersion(0xFF))
    ));
}

#[test]
fn test_validate_base_response_unset_r_bit() {
    // Correct length and version but R bit is not set
    let mut bb = BytesMut::with_capacity(HEADER_SIZE);
    bb.put_u8(VersionCode::Pcp as u8);
    bb.put_u8(0x01); // opcode with R MSb unset
    bb.put_bytes(0, 22); // rest of header unchecked
    let err = validate_base_response(&mut bb, OperationCode::Map).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::ResponseBitNotSet(0x01))
    ));
}

#[test]
fn test_validate_base_response_success() {
    // 24 bytes, correct version, opcode, result code = Success
    let mut bb = BytesMut::with_capacity(HEADER_SIZE);
    bb.put_u8(VersionCode::Pcp as u8);
    bb.put_u8(0x80 | OperationCode::Map as u8); // opcode with R MSb set
    bb.put_u8(0x00); // reserved
    bb.put_u8(ResultCode::Success as u8);
    bb.put_u32(10); // lifetime
    bb.put_u32(20); // epoch
    bb.put_bytes(0, 12); // reserved
    let res = validate_base_response(&mut bb, OperationCode::Map).unwrap();
    assert_eq!(res.lifetime_seconds, 10);
    assert_eq!(res.gateway_epoch_seconds, 20);
}

#[test]
fn test_validate_base_response_natpmp_version_full_response() {
    // A ≥24-byte response with version 0 (NAT-PMP) should return UnsupportedVersion(NatPmp).
    let mut bb = BytesMut::with_capacity(HEADER_SIZE);
    bb.put_u8(VersionCode::NatPmp as u8); // version 0
    bb.put_bytes(0, 23); // rest of header
    let err = validate_base_response(&mut bb, OperationCode::Map).unwrap_err();
    assert!(
        matches!(err, Failure::UnsupportedVersion(VersionCode::NatPmp)),
        "Expected UnsupportedVersion(NatPmp) for NAT-PMP version in full response, got: {err:?}"
    );
}

#[test]
fn test_validate_base_response_short_natpmp_unsupported_version() {
    // A short response (< 24 bytes) with NAT-PMP version and UnsupportedVersion result code.
    // This is the standard NAT-PMP server rejection path.
    let mut bb = BytesMut::with_capacity(4);
    bb.put_u8(VersionCode::NatPmp as u8); // version 0
    bb.put_u8(0x80); // opcode with R bit set
    bb.put_u8(0x00); // first byte of NAT-PMP u16 result code / PCP reserved byte
    bb.put_u8(ResultCode::UnsupportedVersion as u8); // PCP result code byte / NAT-PMP result code LSB
    let err = validate_base_response(&mut bb, OperationCode::Map).unwrap_err();
    assert!(matches!(
        err,
        Failure::UnsupportedVersion(VersionCode::NatPmp)
    ));
}

/// Ensure all error result codes are correctly mapped to Failure variants, including additional failure context.
#[test]
fn test_validate_base_response_error_result_codes() {
    /// Helper to build a 24-byte PCP response with the given result code and lifetime.
    fn make_pcp_response(result_code: ResultCode, lifetime: u32) -> BytesMut {
        let mut bb = BytesMut::with_capacity(HEADER_SIZE);
        bb.put_u8(VersionCode::Pcp as u8);
        bb.put_u8(0x80 | OperationCode::Map as u8);
        bb.put_u8(0x00); // reserved
        bb.put_u8(result_code as u8);
        bb.put_u32(lifetime);
        bb.put_u32(100); // epoch
        bb.put_bytes(0, 12); // reserved
        bb
    }

    // `NotAuthorized` includes the lifetime as retry-after in seconds.
    let mut bb = make_pcp_response(ResultCode::NotAuthorized, 30);
    assert!(matches!(
        validate_base_response(&mut bb, OperationCode::Map).unwrap_err(),
        Failure::NotAuthorized(30)
    ));

    let mut bb = make_pcp_response(ResultCode::MalformedRequest, 0);
    assert!(matches!(
        validate_base_response(&mut bb, OperationCode::Map).unwrap_err(),
        Failure::MalformedRequest
    ));

    // `NetworkFailure` includes the lifetime as retry-after in seconds.
    let mut bb = make_pcp_response(ResultCode::NetworkFailure, 60);
    assert!(matches!(
        validate_base_response(&mut bb, OperationCode::Map).unwrap_err(),
        Failure::NetworkFailure(60)
    ));

    // `NoResources` includes the lifetime as retry-after in seconds.
    let mut bb = make_pcp_response(ResultCode::NoResources, 120);
    assert!(matches!(
        validate_base_response(&mut bb, OperationCode::Map).unwrap_err(),
        Failure::NoResources(120)
    ));

    let mut bb = make_pcp_response(ResultCode::UnsupportedProtocol, 0);
    assert!(matches!(
        validate_base_response(&mut bb, OperationCode::Map).unwrap_err(),
        Failure::UnsupportedProtocol
    ));

    let mut bb = make_pcp_response(ResultCode::AddressMismatch, 0);
    assert!(matches!(
        validate_base_response(&mut bb, OperationCode::Map).unwrap_err(),
        Failure::AddressMismatch
    ));

    let mut bb = make_pcp_response(ResultCode::ExcessiveRemotePeers, 0);
    assert!(matches!(
        validate_base_response(&mut bb, OperationCode::Map).unwrap_err(),
        Failure::ExcessiveRemotePeers
    ));
}

#[test]
fn test_validate_base_response_wrong_opcode() {
    let mut bb = BytesMut::with_capacity(HEADER_SIZE);
    bb.put_u8(VersionCode::Pcp as u8);
    bb.put_u8(0x80 | OperationCode::Peer as u8); // Peer opcode
    bb.put_u8(0x00);
    bb.put_u8(ResultCode::Success as u8);
    bb.put_u32(10);
    bb.put_u32(20);
    bb.put_bytes(0, 12);
    let err = validate_base_response(&mut bb, OperationCode::Map).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::IncorrectOpcode {
            received: OperationCode::Peer,
            expected: OperationCode::Map
        })
    ));
}

#[test]
fn test_protocol_to_byte() {
    // Per IANA protocol numbers: TCP=6, UDP=17
    assert_eq!(protocol_to_byte(InternetProtocol::Tcp), 6);
    assert_eq!(protocol_to_byte(InternetProtocol::Udp), 17);
}

#[test]
fn test_fixed_size_addr_v4() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let v6 = fixed_size_addr(ip);
    // IPv4-mapped IPv6: ::ffff:192.168.1.1
    assert_eq!(v6, Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped());
    assert_eq!(v6.to_ipv4_mapped(), Some(Ipv4Addr::new(192, 168, 1, 1)));
}

#[test]
fn test_fixed_size_addr_v6() {
    let v6_orig = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let ip = IpAddr::V6(v6_orig);
    assert_eq!(fixed_size_addr(ip), v6_orig);
}

#[test]
fn test_read_ip6_addr() {
    let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let octets = addr.octets();
    let mut reader = &octets[..];
    let parsed = read_ip6_addr(&mut reader);
    assert_eq!(parsed, addr);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn test_validate_nonce_success() {
    let nonce: Nonce = [0xDEADBEEF, 0x00C0FFEE, 0x12345678];
    let mut buf = BytesMut::with_capacity(12);
    buf.put_u32(nonce[0]);
    buf.put_u32(nonce[1]);
    buf.put_u32(nonce[2]);
    let mut reader = &buf[..];
    assert!(validate_nonce(&mut reader, nonce).is_ok());
}

#[test]
fn test_validate_nonce_mismatch() {
    let nonce: Nonce = [0xDEADBEEF, 0x00C0FFEE, 0x12345678];
    let mut buf = BytesMut::with_capacity(12);
    buf.put_u32(0x11111111); // wrong
    buf.put_u32(nonce[1]);
    buf.put_u32(nonce[2]);
    let mut reader = &buf[..];
    assert!(matches!(
        validate_nonce(&mut reader, nonce).unwrap_err(),
        Failure::Nonce
    ));
}

#[test]
fn test_validate_port_success() {
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u16(8080);
    let mut reader = &buf[..];
    assert!(validate_port(&mut reader, 8080).is_ok());
}

#[test]
fn test_validate_port_mismatch() {
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u16(9090);
    let mut reader = &buf[..];
    assert_eq!(validate_port(&mut reader, 8080).unwrap_err(), 9090);
}

#[test]
fn test_validate_protocol_tcp() {
    let mut buf = BytesMut::with_capacity(1);
    buf.put_u8(6); // TCP per IANA
    let mut reader = &buf[..];
    assert!(validate_protocol(&mut reader, Some(InternetProtocol::Tcp)).is_ok());
}

#[test]
fn test_validate_protocol_udp() {
    let mut buf = BytesMut::with_capacity(1);
    buf.put_u8(17); // UDP per IANA
    let mut reader = &buf[..];
    assert!(validate_protocol(&mut reader, Some(InternetProtocol::Udp)).is_ok());
}

#[test]
fn test_validate_protocol_none_expects_zero() {
    // When protocol is None (all-protocols mapping), expect byte 0.
    let mut buf = BytesMut::with_capacity(1);
    buf.put_u8(0);
    let mut reader = &buf[..];
    assert!(validate_protocol(&mut reader, None).is_ok());
}

#[test]
fn test_validate_protocol_mismatch() {
    let mut buf = BytesMut::with_capacity(1);
    buf.put_u8(17); // UDP
    let mut reader = &buf[..];
    let err = validate_protocol(&mut reader, Some(InternetProtocol::Tcp)).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::IncorrectProtocol {
            received: 17,
            expected: Some(InternetProtocol::Tcp)
        })
    ));
}

#[test]
fn test_response_to_opcode_map() {
    assert_eq!(
        response_to_opcode(0x80 | OperationCode::Map as u8).unwrap(),
        OperationCode::Map
    );
}

#[test]
fn test_response_to_opcode_peer() {
    assert_eq!(
        response_to_opcode(0x80 | OperationCode::Peer as u8).unwrap(),
        OperationCode::Peer
    );
}

#[test]
fn test_response_to_opcode_invalid() {
    // Opcode 0x7F with R bit set → invalid opcode
    assert!(response_to_opcode(0xFF).is_err());
}

#[test]
fn test_write_base_request_ipv4() {
    let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let mut buf = [0u8; HEADER_SIZE];
    let mut bb = &mut buf[..];
    let suggested_ip = write_base_request(OperationCode::Map, client, None, &mut bb, 7200);

    // Version should be 2 (PCP)
    assert_eq!(buf[0], VersionCode::Pcp as u8);
    // Opcode should be Map (1) with R bit unset
    assert_eq!(buf[1], OperationCode::Map as u8);
    // Reserved (2 bytes)
    assert_eq!(buf[2], 0);
    assert_eq!(buf[3], 0);
    // Lifetime (4 bytes, big-endian)
    assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), 7200);
    // Client IP: IPv4-mapped IPv6 for 192.168.1.100
    let client_ip6 = Ipv4Addr::new(192, 168, 1, 100).to_ipv6_mapped();
    assert_eq!(&buf[8..24], &client_ip6.octets());
    // Suggested external IP should be IPv4-mapped unspecified when None
    assert_eq!(suggested_ip, Ipv4Addr::UNSPECIFIED.to_ipv6_mapped());
}
