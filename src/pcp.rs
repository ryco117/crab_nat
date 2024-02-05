use std::net::IpAddr;

use bytes::{Buf as _, BufMut as _};

use crate::{helpers, natpmp::RECOMMENDED_MAPPING_LIFETIME_SECONDS, Version};

/// The RFC states that the first response timeout "SHOULD be 3 seconds."
/// <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1>
pub const FIRST_TIMEOUT_SECONDS: u32 = 3;

pub const MAX_TIMEOUT_SECONDS: u32 = 1024;

/// PCP has a maximum size of 1100 bytes, see <https://www.rfc-editor.org/rfc/rfc6887#section-7>.
pub const MAX_DATAGRAM_SIZE: usize = 1100;

/// Valid result codes from a PCP response.
/// See <https://www.rfc-editor.org/rfc/rfc6887#section-7.4>
#[derive(num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum ResultCode {
    Success,
    UnsupportedVersion,
    NotAuthorized,
    MalformedRequest,
    UnsupportedOpcode,
    UnsupportedOption,
    MalformedOption,
    NetworkFailure,
    NoResources,
    UnsupportedProtocol,
    UserExceededQuota,
    CannotProvideExternal,
    AddressMismatch,
    ExcessiveRemotePeers,
}

/// Operation codes for NAT-PMP.
#[derive(Debug, num_enum::TryFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum OperationCode {
    ///
    Announce,
    /// Map a UDP port on the gateway.
    Map,
    /// Map a TCP port on the gateway.
    Peer,
}

// https://www.rfc-editor.org/rfc/rfc6887#section-8.1
pub async fn try_port_mapping(gateway: IpAddr, client: IpAddr) -> anyhow::Result<()> {
    let socket = helpers::new_socket(gateway).await?;

    // Need to connect to a gateway using the same internet protocol version as the client.
    if gateway.is_ipv4() != client.is_ipv4() {
        anyhow::bail!("Gateway and client addresses must be of the same IP version")
    }

    // PCP addresses are always specified as 128 bit addresses, <https://www.rfc-editor.org/rfc/rfc6887#section-5>.
    // We need to map `Ipv4Addr` accoriding to RFC4291 <https://www.rfc-editor.org/rfc/rfc4291>.
    let client_ip6_bytes = match client {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
    .octets();

    let mut bb = bytes::BytesMut::with_capacity(MAX_DATAGRAM_SIZE << 1);

    // Create the mapping request header.
    bb.put_u8(Version::Pcp as u8);
    bb.put_u8(opcode_to_request(OperationCode::Map));
    bb.put_u16(0); // Reserved.
    bb.put_u32(RECOMMENDED_MAPPING_LIFETIME_SECONDS);
    bb.put(&client_ip6_bytes[..]);

    // .....

    // Send the request to the gateway.
    let request = bb.split();
    socket.send(&request).await?;

    // TODO: https://www.rfc-editor.org/rfc/rfc6887#section-6 indicates "exponentially increasing intervals"[pg.12]
    // on for retransmissions, similar to NAT-PMP. There is an opportunity to leverage common code between the two protocols.
    // https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1 Expands on this in detail.
    let n = socket.recv_buf(&mut bb).await?;

    // All valid PCP responses have at least 24 bytes, see <https://www.rfc-editor.org/rfc/rfc6887#section-7.2>.
    if n < 24 {
        anyhow::bail!("Received a response that is too short to be valid")
    }

    // Parse the response.
    let v = Version::try_from(bb.get_u8())?;
    if v != Version::Pcp {
        anyhow::bail!("Received a response with an unexpected version {v:?}")
    }
    let op = response_to_opcode(bb.get_u8())?;
    if op != OperationCode::Map {
        anyhow::bail!("Received a response with an unexpected operation code {op:?}")
    }

    let _ = bb.get_u8(); // Reserved.
    let result_code = ResultCode::try_from(bb.get_u8())?;

    // On error, lifetime indicates the number of seconds until the error is expected to be resolved.
    let lifetime_seconds = bb.get_u32();
    let epoch_seconds = bb.get_u32();

    // Reserved. Returns the last 96 bits of the 128 bit address on failure. Must be ignored on success.
    let _ = [bb.get_u32(), bb.get_u32(), bb.get_u32()];

    Ok(())
}

/// Request `OperationCode` bits are the same as the abstract `OperationCode`s, but left shifted by one.
fn opcode_to_request(op: OperationCode) -> u8 {
    (op as u8) << 1
}

/// Response `OperationCode` bits are the same as the request `OperationCode`s, but with the `1` bit set.
/// This function subtracts the `1` from the response bits, right shifts to align with the 7 bit abstract `OperationCode`,
/// and attempts to parse as an `OperationCode`.
fn response_to_opcode(
    op: u8,
) -> Result<OperationCode, num_enum::TryFromPrimitiveError<OperationCode>> {
    OperationCode::try_from((op - 1) >> 1)
}
