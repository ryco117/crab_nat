use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use bytes::{Buf as _, BufMut as _, BytesMut};

use crate::{
    helpers::{self, RequestSendError},
    InternetProtocol, PortMapping, PortMappingType, TimeoutConfig, VersionCode,
    SANE_MAX_REQUEST_RETRIES,
};

/// The RFC states that the first response timeout "SHOULD be 3 seconds."
/// <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1>
pub const FIRST_TIMEOUT_SECONDS: u64 = 3;

/// The RFC states that the maximum response timeout "SHOULD be 1024 seconds."
/// <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1>
pub const MAX_TIMEOUT_SECONDS: u64 = 1024;

/// PCP has a maximum size of 1100 bytes, see <https://www.rfc-editor.org/rfc/rfc6887#section-7>.
pub const MAX_DATAGRAM_SIZE: usize = 1100;

/// The default `TimeoutConfig` for PCP requests.
const TIMEOUT_CONFIG_DEFAULT: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_secs(FIRST_TIMEOUT_SECONDS),
    max_retries: SANE_MAX_REQUEST_RETRIES,
    max_retry_timeout: Some(Duration::from_secs(MAX_TIMEOUT_SECONDS)),
};

/// Valid result codes from a PCP response.
/// See <https://www.rfc-editor.org/rfc/rfc6887#section-7.4>
#[derive(Debug, displaydoc::Display, thiserror::Error, PartialEq, num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum ResultCode {
    /// Success. Will not be returned as an error.
    Success,

    /// The server does not support this version of the protocol.
    UnsupportedVersion,

    /// The server did not authorize the operation.
    NotAuthorized,

    /// The request was formatted incorrectly.
    MalformedRequest,

    /// The server does not support the requested operation.
    UnsupportedOpcode,

    /// The server does not support a required option.
    UnsupportedOption,

    /// An option was formatted incorrectly.
    MalformedOption,

    /// The server is experiencing a temporary network failure.
    NetworkFailure,

    /// The server is lacking resources to complete the request.
    NoResources,

    /// The server does not support the requested protocol.
    UnsupportedProtocol,

    /// Our port mapping quota with the server has been reached.
    UserExceededQuota,

    /// The server cannot provide the requested external address.
    CannotProvideExternal,

    /// The given client address differs from what the server sees.
    AddressMismatch,

    /// The server is not able to create the requested filters.
    ExcessiveRemotePeers,
}

/// Operation codes for NAT-PMP.
#[derive(Debug, num_enum::TryFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum OperationCode {
    /// Map a UDP port on the gateway.
    Map = 1,
    /// Map a TCP port on the gateway.
    Peer,
}

#[derive(Debug, thiserror::Error)]
/// Errors that may occur when trying to map a port on the gateway, categorized by the root of the issue.
pub enum Failure {
    /// Failed to bind, connect, read, or write to a UDP socket.
    #[error("UDP socket error: {0}")]
    Socket(std::io::Error),

    /// The gateway was unreachable within the timeout.
    #[error("Gateway did not respond within the timeout")]
    Timeout,

    /// The gateway did not give a valid response according to the NAT-PMP protocol.
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// The gateway gave a valid response, but it was an error.
    /// The `ResultCode` is guaranteed to not be `ResultCode::Success`.
    #[error("Gateway error: {0}")]
    ResultCode(ResultCode),
}

impl From<RequestSendError> for Failure {
    fn from(e: RequestSendError) -> Self {
        match e {
            RequestSendError::Socket(e) => Failure::Socket(e),
            RequestSendError::Timeout => Failure::Timeout,
        }
    }
}

/// Attempts to map a port on the gateway using PCP.
/// Will try to use the given external port if it is `Some`, otherwise it will let the gateway choose.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_port_mapping(
    gateway: IpAddr,
    client: IpAddr,
    protocol: InternetProtocol,
    internal_port: u16,
    req_external_port: Option<u16>,
    lifetime_seconds: u32,
    timeout_config: Option<TimeoutConfig>,
) -> Result<PortMapping, Failure> {
    let timeout_config = timeout_config.unwrap_or(TIMEOUT_CONFIG_DEFAULT);
    let PcpResponse { n, mut bb, nonce } = try_send_map_request(
        gateway,
        client,
        protocol,
        internal_port,
        req_external_port,
        lifetime_seconds,
        timeout_config,
    )
    .await?;

    // All valid PCP responses have at least 24 bytes, see <https://www.rfc-editor.org/rfc/rfc6887#section-7.2>.
    if n < 24 {
        let bits = &bb[..n];

        // Check if the resposne header matches a `natpmp::ResultCode::UnsupportedVersion` since older devices may not support PCP.
        if n >= 4
            && bits[0] == 0
            && crate::natpmp::ResultCode::try_from((u16::from(bits[2]) << 8) + u16::from(bits[3]))
                .is_ok_and(|r| r == crate::natpmp::ResultCode::UnsupportedVersion)
        {
            return Err(Failure::ResultCode(ResultCode::UnsupportedVersion));
        }

        return Err(Failure::InvalidResponse(format!(
            "Too few bytes received: {bits:X?}"
        )));
    }

    // Parse the PCP response header.
    let v = VersionCode::try_from(bb.get_u8())
        .map_err(|v| Failure::InvalidResponse(format!("Invalid version: {v:#}")))?;
    if v != VersionCode::Pcp {
        return Err(Failure::InvalidResponse(format!(
            "Unsupported version: {v:?}"
        )));
    }
    let op = response_to_opcode(bb.get_u8())
        .map_err(|op| Failure::InvalidResponse(format!("Invalid operation code: {op:#}")))?;
    if op != OperationCode::Map {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect opcode: {op:?}"
        )));
    }
    let _ = bb.get_u8(); // Reserved.
    let result_code = ResultCode::try_from(bb.get_u8())
        .map_err(|r| Failure::InvalidResponse(format!("Invalid result code: {r:#}")))?;

    // On error, lifetime indicates the number of seconds until the error is expected to be resolved.
    let lifetime_seconds = bb.get_u32();
    let epoch_seconds = bb.get_u32();

    #[cfg(debug_assertions)]
    println!("DEBUG Received a response with result code {result_code:#} and lifetime {lifetime_seconds} seconds, at {epoch_seconds}");

    if result_code != ResultCode::Success {
        // The server gave us a correct response, but it was an error.
        return Err(Failure::ResultCode(result_code));
    }

    // Reserved. Returns the last 96 bits of the 128 bit address on failure. Must be ignored on success.
    let _ = [bb.get_u32(), bb.get_u32(), bb.get_u32()];

    // Validate the mapping response values.
    let response_nonce = [bb.get_u32(), bb.get_u32(), bb.get_u32()];
    if response_nonce != nonce {
        // If we received a message with a different nonce, fail with a timeout to retry.
        return Err(Failure::Timeout);
    }
    let response_protocol = bb.get_u8();
    if response_protocol != protocol_to_byte(protocol) {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect protocol: {response_protocol:?}"
        )));
    }
    let _ = [bb.get_u8(), bb.get_u8(), bb.get_u8()]; // Reserved.

    let response_internal_port = bb.get_u16();
    if response_internal_port != internal_port {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect internal port returned: {response_internal_port:?}"
        )));
    }

    // The external port assigned to our mapping. The server may not use the requested port, if present.
    let external_port = bb.get_u16();

    // The external IP address assigned to our mapping.
    let external_ip = Ipv6Addr::new(
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
    );
    let external_ip = if let Some(ip) = external_ip.to_ipv4_mapped() {
        IpAddr::V4(ip)
    } else {
        IpAddr::V6(external_ip)
    };
    #[cfg(debug_assertions)]
    println!("DEBUG Server assigned us external IP {external_ip:#}");

    Ok(PortMapping {
        gateway,
        protocol,
        internal_port,
        external_port,
        lifetime_seconds,
        expiration: std::time::Instant::now() + Duration::from_secs(u64::from(lifetime_seconds)),
        mapping_type: PortMappingType::Pcp { client },
        timeout_config,
    })
}

/// Attempts to remove a PCP mapping on the gateway.
/// Using a local port of `0` will remove all port mappings for our client with the given protocol.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_drop_mapping(
    gateway: IpAddr,
    client: IpAddr,
    protocol: InternetProtocol,
    local_port: u16,
    timeout_config: Option<TimeoutConfig>,
) -> Result<(), Failure> {
    // Mapping deletion is specified by the same operation code and format as mapping creation.
    // The difference is that the lifetime and external port must be set to `0`.
    let PortMapping {
        internal_port,
        external_port,
        lifetime_seconds,
        ..
    } = try_port_mapping(
        gateway,
        client,
        protocol,
        local_port,
        Some(0),
        0,
        timeout_config,
    )
    .await?;

    // Check that the response is correct for a deletion request.
    if internal_port != local_port || external_port != 0 || lifetime_seconds != 0 {
        return Err(Failure::InvalidResponse(format!(
            "Invalid response to deletion request: {internal_port} {external_port} {lifetime_seconds:?}"
        )));
    }

    Ok(())
}

/// Helper object to store the response from a PCP request, including the session nonce.
struct PcpResponse {
    /// The number of bytes in the response.
    pub n: usize,
    /// Bytestream containing the response. Only the first `n` bytes are valid.
    pub bb: BytesMut,
    /// The nonce from the request.
    pub nonce: [u32; 3],
}

/// Helper function to try to create and send a PCP request and return the gateway's response, if any.
async fn try_send_map_request(
    gateway: IpAddr,
    client: IpAddr,
    protocol: InternetProtocol,
    internal_port: u16,
    req_external_port: Option<u16>,
    lifetime_seconds: u32,
    timeout_config: TimeoutConfig,
) -> Result<PcpResponse, Failure> {
    let socket = helpers::new_socket(gateway)
        .await
        .map_err(Failure::Socket)?;

    // PCP addresses are always specified as 128 bit addresses, <https://www.rfc-editor.org/rfc/rfc6887#section-5>.
    // We need to map `Ipv4Addr` accoriding to RFC4291 <https://www.rfc-editor.org/rfc/rfc4291>.
    let (client_ip6_bytes, zero_addr_ip6_bytes) = match client {
        IpAddr::V4(v4) => (v4.to_ipv6_mapped(), Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()),
        IpAddr::V6(v6) => (v6, Ipv6Addr::UNSPECIFIED),
    };

    let mut bb = bytes::BytesMut::with_capacity(MAX_DATAGRAM_SIZE << 1);

    // Create the common PCP request header.
    bb.put_u8(VersionCode::Pcp as u8);
    bb.put_u8(opcode_to_request(OperationCode::Map));
    bb.put_u16(0); // Reserved.
    bb.put_u32(lifetime_seconds);
    bb.put(&client_ip6_bytes.octets()[..]);

    // Generate 96 random bits for the nonce.
    let nonce: [u32; 3] = [rand::random(), rand::random(), rand::random()];

    // Create the mapping specific request.
    bb.put_u32(nonce[0]);
    bb.put_u32(nonce[1]);
    bb.put_u32(nonce[2]);
    bb.put_u8(protocol_to_byte(protocol));
    bb.put(&[0u8; 3][..]); // Reserved.
    bb.put_u16(internal_port);
    bb.put_u16(req_external_port.unwrap_or_default());
    bb.put(&zero_addr_ip6_bytes.octets()[..]); // No preference on external address.

    // Send the request to the gateway.
    let request = bb.split();

    // https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1 TODO: Expands on PCP timing in detail. Requires randomized timeouts.
    let n = helpers::try_send_until_response(timeout_config, &socket, &request, &mut bb)
        .await
        .map_err(Failure::from)?;

    Ok(PcpResponse { n, bb, nonce })
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

/// Convert the `InternetProtocol` enum into the byte expected by the PCP protocol.
fn protocol_to_byte(protocol: InternetProtocol) -> u8 {
    // RFC specifies it uses values from IANA, <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>.
    match protocol {
        InternetProtocol::Tcp => 6,
        InternetProtocol::Udp => 17,
    }
}
