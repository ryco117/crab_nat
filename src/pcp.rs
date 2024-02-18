use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
    time::Duration,
};

use bytes::{Buf as _, BufMut as _, BytesMut};
use rand::Rng as _;

use crate::{
    helpers::{self, RequestSendError},
    InternetProtocol, PortMapping, PortMappingOptions, PortMappingType, TimeoutConfig, VersionCode,
    RECOMMENDED_MAPPING_LIFETIME_SECONDS, SANE_MAX_REQUEST_RETRIES,
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

/// A unqie session identifier for a PCP client.
pub type Nonce = [u32; 3];

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
    /// Create a port mapping on the gateway.
    Map = 1,

    /// Map outbound requests to a peer through an address on the gateway.
    Peer,
}

/// Errors that may occur when trying to map a port on the gateway, categorized by the root of the issue.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// Failed to bind, connect, read, or write to a UDP socket.
    #[error("UDP socket error: {0}")]
    Socket(std::io::Error),

    /// The gateway was unreachable within the timeout.
    #[error("Gateway did not respond within the timeout")]
    Timeout,

    /// Our UDP socket received a nonce we weren't expecting.
    #[error("Incorrect nonce received from the gateway")]
    Nonce,

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

/// The values that must be explicitly defined for all PCP map requests.
#[derive(Clone, Copy)]
pub struct BaseMapRequest {
    pub gateway: IpAddr,
    pub client: IpAddr,
    pub protocol: InternetProtocol,
    pub internal_port: u16,
}
impl BaseMapRequest {
    /// Create a new `BaseMapRequest` with the given gateway, client, protocol, and internal port.
    #[must_use]
    pub fn new(
        gateway: IpAddr,
        client: IpAddr,
        protocol: InternetProtocol,
        internal_port: u16,
    ) -> Self {
        Self {
            gateway,
            client,
            protocol,
            internal_port,
        }
    }
}

/// Attempts to map a port on the gateway using PCP.
/// An internal port of `0` will forward all ports on this protocol to our client address.
/// Will try to use the given external port if it is `Some`, otherwise it will let the gateway choose.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_port_mapping(
    base: BaseMapRequest,
    session_nonce: Option<Nonce>,
    suggested_external_ip: Option<IpAddr>,
    mapping_options: PortMappingOptions,
) -> Result<PortMapping, Failure> {
    // Ensure that a lifetime of `0` is only used for valid delete requests.
    // See section 15.1, <https://www.rfc-editor.org/rfc/rfc6887#section-15.1>.
    if mapping_options.lifetime_seconds.is_some_and(|l| l == 0)
        && (suggested_external_ip.is_some() || mapping_options.external_port.is_some())
    {
        return Err(Failure::ResultCode(ResultCode::MalformedRequest));
    }

    let timeout_config = mapping_options
        .timeout_config
        .unwrap_or(TIMEOUT_CONFIG_DEFAULT);

    // Use an existing session nonce or generate 96 new random bits.
    let nonce: Nonce =
        session_nonce.unwrap_or_else(|| [rand::random(), rand::random(), rand::random()]);

    let PcpResponse { n, mut bb } = try_send_map_request(
        base,
        nonce,
        mapping_options.external_port,
        suggested_external_ip,
        mapping_options
            .lifetime_seconds
            .unwrap_or(RECOMMENDED_MAPPING_LIFETIME_SECONDS),
        timeout_config,
    )
    .await?;

    // Validate the response header.
    let ResponseHeader {
        lifetime_seconds,
        gateway_epoch_seconds,
    } = validate_base_response(&mut bb)?;

    let BaseMapRequest {
        gateway,
        client,
        protocol,
        internal_port,
    } = base;

    // Ensure we can read the rest of the map response.
    if n < 60 {
        let bits = &bb[..n];
        return Err(Failure::InvalidResponse(format!(
            "Too few bytes received: {n}, expected 60: {bits:X?}"
        )));
    }

    // Validate the mapping response values.
    validate_nonce(&mut bb, nonce)?;
    validate_protocol(&mut bb, protocol)?;
    bb.advance(3); // Reserved.
    validate_port(&mut bb, internal_port).map_err(|r| {
        Failure::InvalidResponse(format!(
            "Incorrect internal port {r}, expected {internal_port}",
        ))
    })?;

    // The external port assigned to our mapping. The server may not use the requested port, if present.
    let external_port = bb.get_u16();

    // The external IP address assigned to our mapping.
    let external_ip = read_ip6_addr(&mut bb);
    let external_ip = if let Some(ip) = external_ip.to_ipv4_mapped() {
        IpAddr::V4(ip)
    } else {
        IpAddr::V6(external_ip)
    };

    Ok(PortMapping {
        gateway,
        protocol,
        internal_port,
        external_port,
        lifetime_seconds,
        expiration: std::time::Instant::now() + Duration::from_secs(u64::from(lifetime_seconds)),
        gateway_epoch_seconds,
        mapping_type: PortMappingType::Pcp {
            client,
            nonce,
            external_ip,
        },
        timeout_config,
    })
}

/// Attempts to remove a PCP mapping on the gateway.
/// Using a local port of `0` will remove all port mappings for our client with the given protocol.
/// # Notes
/// This will likely not reduce the remaining lifetime of the mapping, but the result is not guaranteed.
/// See <https://www.rfc-editor.org/rfc/rfc6887#section-15> for more details.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_drop_mapping(
    base: BaseMapRequest,
    nonce: Nonce,
    external_ip: IpAddr,
    external_port: u16,
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
        base,
        Some(nonce),
        Some(external_ip),
        PortMappingOptions {
            external_port: NonZeroU16::new(external_port),
            lifetime_seconds: Some(0),
            timeout_config,
        },
    )
    .await?;

    // Check that the response is correct for a deletion request.
    if internal_port != base.internal_port || lifetime_seconds != 0 {
        return Err(Failure::InvalidResponse(format!(
            "Invalid response to deletion request: {internal_port} {external_port} {lifetime_seconds:?}"
        )));
    }

    Ok(())
}

/// A mapping to a peer's socket address through the gateway.
pub struct PeerMapping {
    pub nonce: Nonce,
    pub gateway: IpAddr,
    pub client: IpAddr,
    pub protocol: InternetProtocol,
    pub internal_port: u16,
    pub external_ip: IpAddr,
    pub external_port: NonZeroU16,
    pub remote_ip: IpAddr,
    pub remote_port: NonZeroU16,
    pub lifetime_seconds: u32,
    pub expiration: std::time::Instant,
    pub gateway_epoch_seconds: u32,
    pub timeout_config: TimeoutConfig,
}

/// Attempts to open a mapping to a remote peer's socket address.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_peer_mapping(
    base: BaseMapRequest,
    session_nonce: Option<Nonce>,
    suggested_external_port: Option<NonZeroU16>,
    suggested_external_ip: Option<IpAddr>,
    remote_port: NonZeroU16,
    remote_ip: IpAddr,
    mapping_options: PortMappingOptions,
) -> Result<PeerMapping, Failure> {
    // Peer requests cannot have an internal port of zero.
    if base.internal_port == 0 {
        return Err(Failure::ResultCode(ResultCode::MalformedRequest));
    }

    let timeout_config = mapping_options
        .timeout_config
        .unwrap_or(TIMEOUT_CONFIG_DEFAULT);

    // Use an existing session nonce or generate 96 new random bits.
    let nonce: Nonce =
        session_nonce.unwrap_or_else(|| [rand::random(), rand::random(), rand::random()]);

    // Create a new UDP socket to communicate with the gateway.
    let socket = helpers::new_socket(base.gateway)
        .await
        .map_err(Failure::Socket)?;

    // Create a bit-stream friendly scratch space.
    let mut bb = bytes::BytesMut::with_capacity(MAX_DATAGRAM_SIZE << 1);

    // Write the common PCP request header.
    let suggested_ip = write_base_request(
        OperationCode::Map,
        base.client,
        suggested_external_ip,
        &mut bb,
        mapping_options
            .lifetime_seconds
            .unwrap_or(RECOMMENDED_MAPPING_LIFETIME_SECONDS),
    );

    // Write the peer specific request.
    bb.put_u32(nonce[0]);
    bb.put_u32(nonce[1]);
    bb.put_u32(nonce[2]);
    bb.put_u8(protocol_to_byte(base.protocol));
    bb.put(&[0u8; 3][..]); // Reserved.
    bb.put_u16(base.internal_port);
    bb.put_u16(suggested_external_port.map_or(0, NonZeroU16::get));
    bb.put(&suggested_ip.octets()[..]);
    bb.put_u16(remote_port.get());
    bb.put_u16(0); // Reserved.
    bb.put(&fixed_size_addr(remote_ip).octets()[..]);
    let request = bb.split();

    // PCP Requires a random value in [0.9, 1.1] be multiplied by the timeout.
    // <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1> Expands on PCP timing in detail.
    let dist = rand::distributions::Uniform::new(0.9, 1.1);
    let fuzz_timeout = |wait: Duration| wait.mul_f64(rand::thread_rng().sample(dist));

    // Try to get a response from the gateway.
    let n =
        helpers::try_send_until_response(timeout_config, &socket, &request, &mut bb, fuzz_timeout)
            .await
            .map_err(Failure::from)?;

    // Validate the response header.
    let header = validate_base_response(&mut bb)?;

    // Ensure we can read the rest of the peer response.
    if n < 80 {
        let bits = &bb[..n];
        return Err(Failure::InvalidResponse(format!(
            "Too few bytes received: {n}, expected 80: {bits:X?}"
        )));
    }

    // Validate the nonce.
    validate_nonce(&mut bb, nonce)?;

    // Validate the internet protocol.
    validate_protocol(&mut bb, base.protocol)?;

    bb.advance(3); // Reserved.

    // Validate the internal port.
    validate_port(&mut bb, base.internal_port).map_err(|r| {
        Failure::InvalidResponse(format!(
            "Incorrect internal port {r}, expected {}",
            base.internal_port,
        ))
    })?;

    // The external port assigned to our mapping. The server may not use the requested port, if present.
    let external_port = NonZeroU16::new(bb.get_u16())
        .ok_or_else(|| Failure::InvalidResponse("Received external port of 0".to_owned()))?;

    // The external IP address assigned to our mapping.
    let external_ip = read_ip6_addr(&mut bb);
    let external_ip = if let Some(ip) = external_ip.to_ipv4_mapped() {
        IpAddr::V4(ip)
    } else {
        IpAddr::V6(external_ip)
    };

    // Validate the remote port.
    validate_port(&mut bb, remote_port.get()).map_err(|r| {
        Failure::InvalidResponse(format!(
            "Incorrect remote port {r}, expected {}",
            remote_port.get(),
        ))
    })?;

    bb.advance(2); // Reserved.

    // Validate remote IP address.
    let response_remote_ip = read_ip6_addr(&mut bb);
    let response_remote_ip = if let Some(ip) = response_remote_ip.to_ipv4_mapped() {
        IpAddr::V4(ip)
    } else {
        IpAddr::V6(response_remote_ip)
    };
    if response_remote_ip != remote_ip {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect remote IP {response_remote_ip}, expected {remote_ip}"
        )));
    }

    Ok(PeerMapping {
        nonce,
        gateway: base.gateway,
        client: base.client,
        protocol: base.protocol,
        internal_port: base.internal_port,
        external_ip,
        external_port,
        remote_ip,
        remote_port,
        lifetime_seconds: header.lifetime_seconds,
        expiration: std::time::Instant::now()
            + Duration::from_secs(u64::from(header.lifetime_seconds)),
        gateway_epoch_seconds: header.gateway_epoch_seconds,
        timeout_config,
    })
}

/// Helper object to store the response from a PCP request, including the session nonce.
struct PcpResponse {
    /// The number of bytes in the response.
    pub n: usize,
    /// Bytestream containing the response. Only the first `n` bytes are valid.
    pub bb: BytesMut,
}

/// Helper function to try to create and send a PCP request and return the gateway's response, if any.
async fn try_send_map_request(
    base: BaseMapRequest,
    nonce: Nonce,
    suggested_external_port: Option<NonZeroU16>,
    suggested_external_ip: Option<IpAddr>,
    lifetime_seconds: u32,
    timeout_config: TimeoutConfig,
) -> Result<PcpResponse, Failure> {
    // Create a new UDP socket to communicate with the gateway.
    let socket = helpers::new_socket(base.gateway)
        .await
        .map_err(Failure::Socket)?;

    // Create a bitstream-friendly scratch space.
    let mut bb = bytes::BytesMut::with_capacity(MAX_DATAGRAM_SIZE << 1);

    // Write the common PCP request header.
    let suggested_ip = write_base_request(
        OperationCode::Map,
        base.client,
        suggested_external_ip,
        &mut bb,
        lifetime_seconds,
    );

    // Create the mapping specific request.
    bb.put_u32(nonce[0]);
    bb.put_u32(nonce[1]);
    bb.put_u32(nonce[2]);
    bb.put_u8(protocol_to_byte(base.protocol));
    bb.put(&[0u8; 3][..]); // Reserved.
    bb.put_u16(base.internal_port);
    bb.put_u16(suggested_external_port.map_or(0, NonZeroU16::get));
    bb.put(&suggested_ip.octets()[..]);

    // Send the request to the gateway.
    let request = bb.split();

    // PCP Requires a random value in [0.9, 1.1] be multiplied by the timeout.
    // <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1> Expands on PCP timing in detail.
    let dist = rand::distributions::Uniform::new(0.9, 1.1);
    let fuzz_timeout = |wait: Duration| wait.mul_f64(rand::thread_rng().sample(dist));

    let n =
        helpers::try_send_until_response(timeout_config, &socket, &request, &mut bb, fuzz_timeout)
            .await
            .map_err(Failure::from)?;

    Ok(PcpResponse { n, bb })
}

/// Information contained in a valid PCP response header for this version.
struct ResponseHeader {
    pub lifetime_seconds: u32,
    pub gateway_epoch_seconds: u32,
}

/// Helper to write the common PCP request header. Returns the suggested external IP address, or the zero address, in fixed-length format.
fn write_base_request(
    op: OperationCode,
    client: IpAddr,
    suggested_external_ip: Option<IpAddr>,
    bb: &mut bytes::BytesMut,
    lifetime_seconds: u32,
) -> Ipv6Addr {
    // PCP addresses are always specified as 128 bit addresses, <https://www.rfc-editor.org/rfc/rfc6887#section-5>.
    // We need to map `Ipv4Addr` to an `Ipv6Addr` accoriding to RFC4291 <https://www.rfc-editor.org/rfc/rfc4291>.
    let (client_ip6, suggested_external_ip6) = match client {
        IpAddr::V4(v4) => (
            v4.to_ipv6_mapped(),
            suggested_external_ip
                .map_or_else(|| Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(), fixed_size_addr),
        ),
        IpAddr::V6(v6) => (
            v6,
            suggested_external_ip.map_or(Ipv6Addr::UNSPECIFIED, fixed_size_addr),
        ),
    };

    // Create the common PCP request header.
    bb.put_u8(VersionCode::Pcp as u8);
    bb.put_u8(opcode_to_request(op));
    bb.put_u16(0); // Reserved.
    bb.put_u32(lifetime_seconds);
    bb.put(&client_ip6.octets()[..]);

    suggested_external_ip6
}

/// Helper function to validate the response from a PCP request. Only validates the first 24 bytes, i.e., the header.
fn validate_base_response(bb: &mut bytes::BytesMut) -> Result<ResponseHeader, Failure> {
    // All valid PCP responses have at least 24 bytes, see <https://www.rfc-editor.org/rfc/rfc6887#section-8.3>, page 26.
    if bb.len() < 24 {
        let n = bb.len();
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
    bb.advance(1); // Reserved.
    let result_code = ResultCode::try_from(bb.get_u8())
        .map_err(|r| Failure::InvalidResponse(format!("Invalid result code: {r:#}")))?;

    // On error, lifetime indicates the number of seconds until the error is expected to be resolved.
    let lifetime_seconds = bb.get_u32();
    let gateway_epoch_seconds = bb.get_u32();

    bb.advance(12); // Reserved.

    if result_code != ResultCode::Success {
        // The server gave us a correct response, but it was an error.
        return Err(Failure::ResultCode(result_code));
    }

    Ok(ResponseHeader {
        lifetime_seconds,
        gateway_epoch_seconds,
    })
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

/// Helper to extract the `Ipv6Addr` from an `IpAddr` or map an `Ipv4Addr` properly.
/// See <https://www.rfc-editor.org/rfc/rfc6887#section-5>.
fn fixed_size_addr(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Read an `Ipv6Addr` from the given `BytesMut`.
/// # Panics
/// This function panics if there is not enough remaining data in self to read the `Ipv6Addr`.
fn read_ip6_addr(bb: &mut bytes::BytesMut) -> Ipv6Addr {
    Ipv6Addr::new(
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
        bb.get_u16(),
    )
}

/// Validate a nonce value received.
fn validate_nonce(bb: &mut bytes::BytesMut, expected_nonce: Nonce) -> Result<(), Failure> {
    let response_nonce = [bb.get_u32(), bb.get_u32(), bb.get_u32()];
    if response_nonce != expected_nonce {
        return Err(Failure::Nonce);
    }
    Ok(())
}

/// Validate a port value received.
fn validate_port(bb: &mut bytes::BytesMut, expected_port: u16) -> Result<(), u16> {
    let response_port = bb.get_u16();
    if response_port != expected_port {
        return Err(response_port);
    }
    Ok(())
}

/// Validate a protocol received.
fn validate_protocol(
    bb: &mut bytes::BytesMut,
    expected_protocol: InternetProtocol,
) -> Result<(), Failure> {
    let response_protocol = bb.get_u8();
    if response_protocol != protocol_to_byte(expected_protocol) {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect protocol {response_protocol}, expected {expected_protocol:?}"
        )));
    }
    Ok(())
}
