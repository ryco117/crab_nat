use super::*;

#[test]
fn test_validate_base_response_too_short() {
    // Less than 24 bytes should return InvalidResponse
    let mut bb = BytesMut::from(&[0u8; 16][..]);
    let err = validate_base_response(&mut bb).unwrap_err();
    assert!(matches!( err, Failure::InvalidResponse(ref msg)
        if msg.contains("Too few bytes")
    ));
}

#[test]
fn test_validate_base_response_invalid_length() {
    // More than 24 bytes but not a multiple of 4 bytes should return InvalidResponse
    let mut bb = BytesMut::from(&[0u8; 27][..]);
    let err = validate_base_response(&mut bb).unwrap_err();
    assert!(matches!( err, Failure::InvalidResponse(ref msg)
        if msg.contains("Invalid response length")
    ));
}

#[test]
fn test_validate_base_response_unsupported_version() {
    // Correct length, but version is not required PCP version 2
    let mut bb = BytesMut::with_capacity(24);
    bb.put_u8(0xFF); // version (invalid)
    bb.put_bytes(0u8, 23); // rest of header unchecked
    let err = validate_base_response(&mut bb).unwrap_err();
    assert!(matches!( err, Failure::InvalidResponse(ref msg)
        if msg.contains("Unknown version")
    ));
}

#[test]
fn test_validate_base_response_unset_r_bit() {
    // Correct length and version but R bit is not set
    let mut bb = BytesMut::with_capacity(24);
    bb.put_u8(VersionCode::Pcp as u8);
    bb.put_u8(0x01); // opcode with R MSb unset
    bb.put_bytes(0, 22); // rest of header unchecked
    let err = validate_base_response(&mut bb).unwrap_err();
    assert!(matches!( err, Failure::InvalidResponse(ref msg)
        if msg.contains("Response R bit (MSb) must be set")
    ));
}

#[test]
fn test_validate_base_response_success() {
    // 24 bytes, correct version, opcode, result code = Success
    let mut bb = BytesMut::with_capacity(24);
    bb.put_u8(VersionCode::Pcp as u8);
    bb.put_u8(0x80 | OperationCode::Map as u8); // opcode with R MSb set
    bb.put_u8(0x00); // reserved
    bb.put_u8(ResultCode::Success as u8);
    bb.put_u32(10); // lifetime
    bb.put_u32(20); // epoch
    bb.put_bytes(0, 12); // reserved
    let res = validate_base_response(&mut bb).unwrap();
    assert_eq!(res.lifetime_seconds, 10);
    assert_eq!(res.gateway_epoch_seconds, 20);
}
