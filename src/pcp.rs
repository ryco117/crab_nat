use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
/// However, this can be very long for modern applications. Using a 1 second default as a compromise.
pub const FIRST_TIMEOUT_SECONDS: u64 = 1;

/// The RFC states that the maximum response timeout "SHOULD be 1024 seconds."
/// <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1>
pub const MAX_TIMEOUT_SECONDS: u64 = 1024;

/// PCP has a maximum size of 1100 bytes, see <https://www.rfc-editor.org/rfc/rfc6887#section-7>.
pub const MAX_DATAGRAM_SIZE: usize = 1100;

/// The default `TimeoutConfig` for PCP requests.
pub const TIMEOUT_CONFIG_DEFAULT: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_secs(FIRST_TIMEOUT_SECONDS),
    max_retries: SANE_MAX_REQUEST_RETRIES,
    max_retry_timeout: Some(Duration::from_secs(MAX_TIMEOUT_SECONDS)),
};

/// A unique session identifier for a PCP client.
pub type Nonce = [u32; 3];

/// Valid result codes from a PCP response.
/// See <https://www.rfc-editor.org/rfc/rfc6887#section-7.4>.
#[derive(
    Clone, Copy, Debug, displaydoc::Display, thiserror::Error, PartialEq, num_enum::TryFromPrimitive,
)]
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

/// Operation codes for NAT-PMP, see <https://www.rfc-editor.org/rfc/rfc6887#section-19.1>.
#[derive(Clone, Copy, Debug, num_enum::TryFromPrimitive, PartialEq)]
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

    /// The gateway gave a version-mismatch response with a closest supported version.
    #[error("Server responded with code: Unsupported version: Closest supported version: {0}")]
    UnsupportedVersion(VersionCode),

    /// The server has not authorized our client to make the requested operation.
    /// An estimation of how long the error will persist is given in seconds.
    #[error("Server responded with code: Not authorized")]
    NotAuthorized(u32),

    /// The request was formatted incorrectly.
    #[error("Server responded with code: Malformed request")]
    MalformedRequest,

    /// The server does not support the requested operation.
    #[error("Server responded with code: Unsupported opcode")]
    UnsupportedOpcode,

    /// The server does not support a required option.
    #[error("Server responded with code: Unsupported option")]
    UnsupportedOption,

    /// An option was formatted incorrectly.
    #[error("Server responded with code: Malformed option")]
    MalformedOption,

    /// The server is experiencing a temporary network failure.
    /// An estimation of how long the error will persist is given in seconds.
    #[error("Server responded with code: Network failure")]
    NetworkFailure(u32),

    /// The server is lacking resources to complete the request.
    /// An estimation of how long the error will persist is given in seconds.
    #[error("Server responded with code: No resources")]
    NoResources(u32),

    /// The server does not support the requested protocol.
    #[error("Server responded with code: Unsupported protocol")]
    UnsupportedProtocol,

    /// Our port mapping quota with the server has been reached.
    /// An estimation of how long the error will persist is given in seconds.
    #[error("Server responded with code: User exceeded quota")]
    UserExceededQuota(u32),

    /// The server cannot provide the requested external address.
    /// An estimation of how long the error will persist is given in seconds.
    #[error("Server responded with code: Cannot provide external")]
    CannotProvideExternal(u32),

    /// The given client address differs from what the server sees.
    #[error("Server responded with code: Address mismatch")]
    AddressMismatch,

    /// The server is not able to create the requested filters.
    #[error("Server responded with code: Excessive remote peers")]
    ExcessiveRemotePeers,
}
impl From<RequestSendError> for Failure {
    fn from(e: RequestSendError) -> Self {
        match e {
            RequestSendError::Socket(e) => Failure::Socket(e),
            RequestSendError::Timeout => Failure::Timeout,
        }
    }
}

/// The values that must be explicitly defined for all PCP single-port and peer mapping requests.
#[derive(Clone, Copy)]
pub struct BaseMapRequest {
    pub gateway: IpAddr,
    pub client: IpAddr,
    pub protocol: InternetProtocol,
    pub internal_port: NonZeroU16,
}
impl BaseMapRequest {
    /// Create a new `BaseMapRequest` with the given gateway, client, protocol, and internal port.
    #[must_use]
    pub fn new(
        gateway: IpAddr,
        client: IpAddr,
        protocol: InternetProtocol,
        internal_port: NonZeroU16,
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
/// Will try to use the given external port if it is `Some`, otherwise it will let the gateway choose.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn port_mapping(
    base: BaseMapRequest,
    session_nonce: Option<Nonce>,
    suggested_external_ip: Option<IpAddr>,
    mapping_options: PortMappingOptions,
) -> Result<PortMapping, Failure> {
    // Create a mapping range for a single port.
    let map_range = MappingRange::Single {
        protocol: base.protocol,
        internal_port: base.internal_port,
        suggested_external_port: mapping_options.external_port,
        suggested_external_ip,
    };

    // Use the internal helper to try to map the port.
    let PortMappingInternal {
        lifetime_seconds,
        gateway_epoch_seconds,
        nonce,
        external_port,
        external_ip,
        timeout_config,
        ..
    } = port_mapping_internal(
        base.gateway,
        base.client,
        session_nonce,
        map_range,
        mapping_options.lifetime_seconds,
        mapping_options.timeout_config,
    )
    .await?;

    // Ensure the external port is not zero.
    let external_port = NonZeroU16::new(external_port)
        .ok_or_else(|| Failure::InvalidResponse("Invalid external port of zero".to_owned()))?;

    Ok(PortMapping {
        gateway: base.gateway,
        protocol: base.protocol,
        internal_port: base.internal_port,
        external_port,
        lifetime_seconds,
        expiration: std::time::Instant::now() + Duration::from_secs(u64::from(lifetime_seconds)),
        gateway_epoch_seconds,
        mapping_type: PortMappingType::Pcp {
            client: base.client,
            nonce,
            external_ip,
        },
        timeout_config,
    })
}

/// A port mapping on the gateway using PCP to map all ports to our client through the PCP server.
#[derive(Clone, Debug)]
pub struct PortMappingAllPorts {
    /// The address of the gateway the mapping is registered with.
    gateway: IpAddr,

    /// The address of the client the mapping is registered to.
    client: IpAddr,

    /// The protocol the mapping is for.
    protocol: Option<InternetProtocol>,

    /// The external IP of our mapping on the gateway.
    external_ip: IpAddr,

    /// The lifetime of the port mapping in seconds.
    lifetime_seconds: u32,

    /// The gateway epoch time when the port mapping was created.
    gateway_epoch_seconds: u32,

    /// The nonce used to create the port mapping.
    nonce: Nonce,

    /// The datetime the port mapping is set to expire at, using this machine's clock.
    expiration: std::time::Instant,

    /// The configuration of the timing of UDP requests made to the gateway.
    pub timeout_config: TimeoutConfig,
}

/// Attempts to map all ports on the gateway to the corresponding port on our client using PCP.
/// If the protocol is `None`, it will try to map all ports for all protocols.
/// Otherwise, only the specified protocol will be mapped.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn port_mapping_all_ports(
    gateway: IpAddr,
    client: IpAddr,
    protocol: Option<InternetProtocol>,
    session_nonce: Option<Nonce>,
    suggested_external_ip: Option<IpAddr>,
    lifetime_seconds: Option<u32>,
    timeout_config: Option<TimeoutConfig>,
) -> Result<PortMappingAllPorts, Failure> {
    let map_range = MappingRange::All {
        protocol,
        suggested_external_ip,
    };

    let PortMappingInternal {
        lifetime_seconds,
        gateway_epoch_seconds,
        nonce,
        external_ip,
        timeout_config,
        ..
    } = port_mapping_internal(
        gateway,
        client,
        session_nonce,
        map_range,
        lifetime_seconds,
        timeout_config,
    )
    .await?;

    Ok(PortMappingAllPorts {
        gateway,
        client,
        protocol,
        external_ip,
        lifetime_seconds,
        gateway_epoch_seconds,
        nonce,
        expiration: std::time::Instant::now() + Duration::from_secs(u64::from(lifetime_seconds)),
        timeout_config,
    })
}

/// The range of port mappings to drop.
/// Either a `Single` port for a given protocol or `All` ports for a single protocols, or all protocols if `None`.
#[derive(Clone, Copy, Debug)]
pub enum DropMappingRange {
    Single {
        protocol: InternetProtocol,
        internal_port: NonZeroU16,
    },
    All {
        protocol: Option<InternetProtocol>,
    },
}

/// Attempts to remove PCP port mappings for our client from the gateway.
/// # Notes
/// This may not reduce the remaining lifetime of the mapping on the PCP server for security reasons.
/// See <https://www.rfc-editor.org/rfc/rfc6887#section-15> for more details.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn try_drop_mapping(
    gateway: IpAddr,
    client: IpAddr,
    nonce: Nonce,
    drop_map_range: DropMappingRange,
    timeout_config: Option<TimeoutConfig>,
) -> Result<(), Failure> {
    // Create a port mapping range depending on the which type was requested.
    let map_range = match drop_map_range {
        DropMappingRange::Single {
            internal_port,
            protocol,
        } => MappingRange::Single {
            internal_port,
            protocol,
            suggested_external_port: None,
            suggested_external_ip: None,
        },
        DropMappingRange::All { protocol } => MappingRange::All {
            protocol,
            suggested_external_ip: None,
        },
    };

    // Mapping deletion is specified by the same operation code and format as mapping creation.
    // The difference is that the lifetime and external port must be set to `0`.
    let PortMappingInternal {
        lifetime_seconds, ..
    } = port_mapping_internal(
        gateway,
        client,
        Some(nonce),
        map_range,
        Some(0),
        timeout_config,
    )
    .await?;

    // Check that the response is correct for a deletion request.
    if lifetime_seconds != 0 {
        return Err(Failure::InvalidResponse(format!(
            "Invalid response to deletion request: {lifetime_seconds}"
        )));
    }

    Ok(())
}

/// A mapping to a peer's socket address through the gateway (i.e., the PCP server).
#[derive(Clone, Debug)]
pub struct PeerMapping {
    /// The address of the gateway the mapping is registered with.
    gateway: IpAddr,

    /// The address of the client the mapping is registered to.
    client: IpAddr,

    /// The protocol the mapping is for.
    protocol: InternetProtocol,

    /// The internal port of our mapping on the client.
    internal_port: NonZeroU16,

    /// The external IP of our mapping on the gateway.
    external_ip: IpAddr,

    /// The external port of our mapping on the gateway.
    external_port: NonZeroU16,

    /// The peer's socket address as seen by the gateway.
    remote_address: SocketAddr,

    /// The lifetime of the peer mapping in seconds.
    lifetime_seconds: u32,

    /// The gateway epoch time when the peer mapping was created.
    gateway_epoch_seconds: u32,

    /// The nonce used to create the peer mapping.
    nonce: Nonce,

    /// The datetime the peer mapping is set to expire at, using this machine's clock.
    expiration: std::time::Instant,

    /// The configuration of the timing of UDP requests made to the gateway.
    pub timeout_config: TimeoutConfig,
}

/// Attempts to open a mapping to a remote peer's socket address.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn peer_mapping(
    base: BaseMapRequest,
    session_nonce: Option<Nonce>,
    suggested_external_ip: Option<IpAddr>,
    remote_address: SocketAddr,
    mapping_options: PortMappingOptions,
) -> Result<PeerMapping, Failure> {
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

    // Extract the remote IP and port from the given `SocketAddr`.
    let (remote_ip, remote_port) = (remote_address.ip(), remote_address.port());

    // Write the peer specific request.
    bb.put_u32(nonce[0]);
    bb.put_u32(nonce[1]);
    bb.put_u32(nonce[2]);
    bb.put_u8(protocol_to_byte(base.protocol));
    bb.put(&[0u8; 3][..]); // Reserved.
    bb.put_u16(base.internal_port.get());
    bb.put_u16(mapping_options.external_port.map_or(0, NonZeroU16::get));
    bb.put(&suggested_ip.octets()[..]);
    bb.put_u16(remote_port);
    bb.put_u16(0); // Reserved.
    bb.put(&fixed_size_addr(remote_ip).octets()[..]);
    let request = bb.split();

    // PCP Requires a random value in [0.9, 1.1] be multiplied by the timeout.
    // <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1> Expands on PCP timing in detail.
    let dist = rand::distr::Uniform::try_from(0.9..=1.1)
        .expect("Failed to initialize uniform distribution");
    let fuzz_timeout = |wait: Duration| wait.mul_f64(rand::rng().sample(dist));

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
    validate_protocol(&mut bb, Some(base.protocol))?;

    bb.advance(3); // Reserved.

    // Validate the internal port.
    let internal_port = base.internal_port;
    validate_port(&mut bb, internal_port.get()).map_err(|r| {
        Failure::InvalidResponse(format!(
            "Incorrect internal port {r}, expected {internal_port}"
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
    validate_port(&mut bb, remote_port).map_err(|r| {
        Failure::InvalidResponse(format!("Incorrect remote port {r}, expected {remote_port}"))
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
        internal_port,
        external_ip,
        external_port,
        remote_address,
        lifetime_seconds: header.lifetime_seconds,
        expiration: std::time::Instant::now()
            + Duration::from_secs(u64::from(header.lifetime_seconds)),
        gateway_epoch_seconds: header.gateway_epoch_seconds,
        timeout_config,
    })
}

/// A successful response to a port mapping request.
struct PortMappingInternal {
    pub lifetime_seconds: u32,
    pub gateway_epoch_seconds: u32,
    pub nonce: Nonce,
    pub external_port: u16,
    pub external_ip: IpAddr,
    pub timeout_config: TimeoutConfig,
}

/// Helper for attempting a port mapping with more permissive input.
/// # Errors
/// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause.
/// # Panics
/// Panics if the `lifetime_seconds` is `Some(0)` and the `map_range` has a suggested external IP
/// or a suggested external port.
async fn port_mapping_internal(
    gateway: IpAddr,
    client: IpAddr,
    nonce: Option<Nonce>,
    map_range: MappingRange,
    lifetime_seconds: Option<u32>,
    timeout_config: Option<TimeoutConfig>,
) -> Result<PortMappingInternal, Failure> {
    // Ensure that a lifetime of `0` is only used for valid delete requests.
    // See section 15.1, <https://www.rfc-editor.org/rfc/rfc6887#section-15.1>.
    #[cfg(debug_assertions)]
    assert!(
        lifetime_seconds.is_none_or(|l| l > 0)
            || match &map_range {
                MappingRange::Single {
                    suggested_external_ip,
                    suggested_external_port,
                    ..
                } => {
                    suggested_external_ip.is_none_or(|ip| ip.is_unspecified())
                        && suggested_external_port.is_none()
                }
                MappingRange::All {
                    suggested_external_ip,
                    ..
                } => suggested_external_ip.is_none_or(|ip| ip.is_unspecified()),
            },
        "Lifetime of 0 is only valid for deletion requests"
    );

    let timeout_config = timeout_config.unwrap_or(TIMEOUT_CONFIG_DEFAULT);

    // Use an existing session nonce or generate 96 new random bits.
    let nonce: Nonce = nonce.unwrap_or_else(|| [rand::random(), rand::random(), rand::random()]);

    let PcpResponse { n, mut bb } = try_send_map_request(
        gateway,
        client,
        nonce,
        map_range,
        lifetime_seconds.unwrap_or(RECOMMENDED_MAPPING_LIFETIME_SECONDS),
        timeout_config,
    )
    .await?;

    // Validate the response header.
    let ResponseHeader {
        lifetime_seconds,
        gateway_epoch_seconds,
    } = validate_base_response(&mut bb)?;

    // Ensure we can read the rest of the map response.
    if n < 60 {
        let bits = &bb[..n];
        return Err(Failure::InvalidResponse(format!(
            "Too few bytes received: {n}, expected 60: {bits:X?}"
        )));
    }

    // Validate the mapping response values.
    validate_nonce(&mut bb, nonce)?;
    validate_protocol(
        &mut bb,
        match map_range {
            MappingRange::Single { protocol, .. } => Some(protocol),
            MappingRange::All { protocol, .. } => protocol,
        },
    )?;
    bb.advance(3); // Reserved.
    let expected_internal_port = if let MappingRange::Single { internal_port, .. } = map_range {
        internal_port.get()
    } else {
        0
    };
    validate_port(&mut bb, expected_internal_port).map_err(|r| {
        Failure::InvalidResponse(format!(
            "Incorrect internal port {r}, expected {expected_internal_port}"
        ))
    })?;

    // The external port assigned to our mapping. The server may not use the suggested port, if present.
    let external_port = bb.get_u16();

    // The external IP address assigned to our mapping.
    let external_ip = read_ip6_addr(&mut bb);
    let external_ip = if let Some(ip) = external_ip.to_ipv4_mapped() {
        IpAddr::V4(ip)
    } else {
        IpAddr::V6(external_ip)
    };

    Ok(PortMappingInternal {
        lifetime_seconds,
        gateway_epoch_seconds,
        nonce,
        external_port,
        external_ip,
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

#[derive(Clone, Copy)]
enum MappingRange {
    Single {
        protocol: InternetProtocol,
        internal_port: NonZeroU16,
        suggested_external_port: Option<NonZeroU16>,
        suggested_external_ip: Option<IpAddr>,
    },
    All {
        protocol: Option<InternetProtocol>,
        suggested_external_ip: Option<IpAddr>,
    },
}

/// Helper function to try to create and send a PCP request and return the gateway's response, if any.
async fn try_send_map_request(
    gateway: IpAddr,
    client: IpAddr,
    nonce: Nonce,
    map_range: MappingRange,
    lifetime_seconds: u32,
    timeout_config: TimeoutConfig,
) -> Result<PcpResponse, Failure> {
    // Create a new UDP socket to communicate with the gateway.
    let socket = helpers::new_socket(gateway)
        .await
        .map_err(Failure::Socket)?;

    // Create a bitstream-friendly scratch space.
    let mut bb = bytes::BytesMut::with_capacity(MAX_DATAGRAM_SIZE << 1);

    // Write the common PCP request header.
    let suggested_ip = write_base_request(
        OperationCode::Map,
        client,
        match map_range {
            MappingRange::Single {
                suggested_external_ip,
                ..
            }
            | MappingRange::All {
                suggested_external_ip,
                ..
            } => suggested_external_ip,
        },
        &mut bb,
        lifetime_seconds,
    );

    // Create the mapping specific request.
    bb.put_u32(nonce[0]);
    bb.put_u32(nonce[1]);
    bb.put_u32(nonce[2]);
    bb.put_u8(if let MappingRange::Single { protocol, .. } = map_range {
        protocol_to_byte(protocol)
    } else {
        0
    });
    bb.put(&[0u8; 3][..]); // Reserved.
    bb.put_u16(
        if let MappingRange::Single { internal_port, .. } = map_range {
            internal_port.get()
        } else {
            0
        },
    );
    bb.put_u16(
        if let MappingRange::Single {
            suggested_external_port,
            ..
        } = map_range
        {
            suggested_external_port.map_or(0, NonZeroU16::get)
        } else {
            0
        },
    );
    bb.put(&suggested_ip.octets()[..]);

    // Send the request to the gateway.
    let request = bb.split();

    // PCP Requires a random value in [0.9, 1.1] be multiplied by the timeout.
    // <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1> Expands on PCP timing in detail.
    let dist = rand::distr::Uniform::try_from(0.9..=1.1)
        .expect("Failed to initialize uniform distribution");
    let fuzz_timeout = |wait: Duration| wait.mul_f64(rand::rng().sample(dist));

    let n =
        helpers::try_send_until_response(timeout_config, &socket, &request, &mut bb, fuzz_timeout)
            .await
            .map_err(Failure::from)?;

    Ok(PcpResponse { n, bb })
}

/// Information contained in a valid PCP response header for this version.
#[derive(Debug)]
struct ResponseHeader {
    pub lifetime_seconds: u32,
    pub gateway_epoch_seconds: u32,
}

/// Helper to write the common PCP request header.
/// Returns the suggested external IP if some, else the zero address, in fixed-length format.
fn write_base_request(
    op: OperationCode,
    client: IpAddr,
    suggested_external_ip: Option<IpAddr>,
    bb: &mut bytes::BytesMut,
    lifetime_seconds: u32,
) -> Ipv6Addr {
    // PCP addresses are always specified as 128 bit addresses, <https://www.rfc-editor.org/rfc/rfc6887#section-5>.
    // We need to map `Ipv4Addr` to an `Ipv6Addr` according to RFC4291 <https://www.rfc-editor.org/rfc/rfc4291>.
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
    let n = bb.len();
    if n < 24 {
        let header_bytes = &bb[..n];

        // Both NAT-PMP and PCP responses have compatible 4-byte headers.
        if n >= 4 {
            let version = header_bytes[0].try_into().map_err(|_| {
                Failure::InvalidResponse(format!("Unknown version: {:X?}", header_bytes[0]))
            })?;

            // Check if it matches a PCP unsupported version code.
            if ResultCode::try_from(header_bytes[3])
                .is_ok_and(|r| r == ResultCode::UnsupportedVersion)
            {
                return Err(Failure::UnsupportedVersion(version));
            }
        }

        // The response is too short to be valid.
        return Err(Failure::InvalidResponse(format!(
            "Too few bytes received: {header_bytes:X?}"
        )));
    }

    // PCP responses are always a multiple of 4 bytes, see <https://www.rfc-editor.org/rfc/rfc6887#section-8.3>, page 26.
    if n % 4 != 0 {
        return Err(Failure::InvalidResponse(format!(
            "Invalid response length. Expected a multiple of 4, got: {n}"
        )));
    }

    // Parse the PCP response header.
    let v = VersionCode::try_from(bb.get_u8())
        .map_err(|v| Failure::InvalidResponse(format!("Unknown version: {v:#}")))?;
    if v != VersionCode::Pcp {
        return Err(Failure::InvalidResponse(format!(
            "Unsupported version: {v:?}"
        )));
    }

    let r_opcode_octet = bb.get_u8();
    if r_opcode_octet & 0x80 == 0 {
        return Err(Failure::InvalidResponse(format!(
            "Response R bit (MSb) must be set: {r_opcode_octet:08b}"
        )));
    }

    let op = response_to_opcode(r_opcode_octet)
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
    // See <https://www.rfc-editor.org/rfc/rfc6887#section-8.3>, page 26.
    let lifetime_seconds = bb.get_u32();
    let gateway_epoch_seconds = bb.get_u32();

    bb.advance(12); // Reserved.

    // Map error result codes to a failure, otherwise continue.
    match result_code {
        ResultCode::Success => Ok(()),
        ResultCode::UnsupportedVersion => Err(Failure::UnsupportedVersion(v)),
        ResultCode::NotAuthorized => Err(Failure::NotAuthorized(lifetime_seconds)),
        ResultCode::MalformedRequest => Err(Failure::MalformedRequest),
        ResultCode::UnsupportedOpcode => Err(Failure::UnsupportedOpcode),
        ResultCode::UnsupportedOption => Err(Failure::UnsupportedOption),
        ResultCode::MalformedOption => Err(Failure::MalformedOption),
        ResultCode::NetworkFailure => Err(Failure::NetworkFailure(lifetime_seconds)),
        ResultCode::NoResources => Err(Failure::NoResources(lifetime_seconds)),
        ResultCode::UnsupportedProtocol => Err(Failure::UnsupportedProtocol),
        ResultCode::UserExceededQuota => Err(Failure::UserExceededQuota(lifetime_seconds)),
        ResultCode::CannotProvideExternal => Err(Failure::CannotProvideExternal(lifetime_seconds)),
        ResultCode::AddressMismatch => Err(Failure::AddressMismatch),
        ResultCode::ExcessiveRemotePeers => Err(Failure::ExcessiveRemotePeers),
    }?;

    Ok(ResponseHeader {
        lifetime_seconds,
        gateway_epoch_seconds,
    })
}

/// Request `OperationCode` bits are the same as the abstract
/// `OperationCode`s but with MSb `R` bit (MSb) unset.
fn opcode_to_request(op: OperationCode) -> u8 {
    op as u8 & 0x7F
}

/// Response `OperationCode` bits are the same as the request
/// `OperationCode`s, but mask out `R` bit (MSb).
fn response_to_opcode(
    op: u8,
) -> Result<OperationCode, num_enum::TryFromPrimitiveError<OperationCode>> {
    OperationCode::try_from(op & 0x7F)
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
/// This function panics if there is not enough remaining data in `bb` to read the `Ipv6Addr`.
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
    expected_protocol: Option<InternetProtocol>,
) -> Result<(), Failure> {
    let response_protocol = bb.get_u8();
    if response_protocol != expected_protocol.map_or(0, protocol_to_byte) {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect protocol {response_protocol}, expected {expected_protocol:?}"
        )));
    }
    Ok(())
}

impl PeerMapping {
    /// Attempts to renew this peer mapping on the gateway, otherwise returns an error.
    /// # Errors
    /// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause.
    pub async fn renew(&mut self) -> Result<(), Failure> {
        // Attempt to renew the existing port mapping on the gateway.
        *self = peer_mapping(
            BaseMapRequest::new(self.gateway, self.client, self.protocol, self.internal_port),
            Some(self.nonce),
            Some(self.external_ip),
            self.remote_address,
            PortMappingOptions {
                external_port: Some(self.external_port),
                lifetime_seconds: Some(self.lifetime_seconds),
                timeout_config: Some(self.timeout_config),
            },
        )
        .await?;
        Ok(())
    }

    /// Attempts to safely delete this peer mapping on the gateway, otherwise returns an error and the `PeerMapping` back.
    /// # Errors
    /// Returns a pair containing a `pcp::Failure` enum, which decomposes into different errors
    /// depending on the cause, and the unmodified mapping.
    pub async fn try_drop(self) -> Result<(), (Failure, Self)> {
        // Attempt to drop the existing port mapping on the gateway.
        peer_mapping(
            BaseMapRequest::new(self.gateway, self.client, self.protocol, self.internal_port),
            Some(self.nonce),
            None,
            self.remote_address,
            PortMappingOptions {
                external_port: None,
                lifetime_seconds: Some(0),
                timeout_config: Some(self.timeout_config),
            },
        )
        .await
        .map_err(|e| (e, self))
        .map(std::mem::drop)
    }

    #[must_use]
    pub fn gateway(&self) -> IpAddr {
        self.gateway
    }
    #[must_use]
    pub fn client(&self) -> IpAddr {
        self.client
    }
    #[must_use]
    pub fn protocol(&self) -> InternetProtocol {
        self.protocol
    }
    #[must_use]
    pub fn internal_port(&self) -> NonZeroU16 {
        self.internal_port
    }
    #[must_use]
    pub fn external_ip(&self) -> IpAddr {
        self.external_ip
    }
    #[must_use]
    pub fn external_port(&self) -> NonZeroU16 {
        self.external_port
    }
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.remote_address
    }
    #[must_use]
    pub fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }
    #[must_use]
    pub fn gateway_epoch_seconds(&self) -> u32 {
        self.gateway_epoch_seconds
    }
    #[must_use]
    pub fn nonce(&self) -> Nonce {
        self.nonce
    }
    #[must_use]
    pub fn expiration(&self) -> std::time::Instant {
        self.expiration
    }
}

impl PortMappingAllPorts {
    /// Attempts to renew this port mapping on the gateway, otherwise returns an error.
    /// # Errors
    /// Returns a `pcp::Failure` enum which decomposes into different errors depending on the cause.
    pub async fn renew(&mut self) -> Result<(), Failure> {
        // Attempt to renew the existing port mapping on the gateway.
        *self = port_mapping_all_ports(
            self.gateway,
            self.client,
            self.protocol,
            Some(self.nonce),
            Some(self.external_ip),
            Some(self.lifetime_seconds),
            Some(self.timeout_config),
        )
        .await?;
        Ok(())
    }

    /// Attempts to safely delete this port mapping on the gateway, otherwise returns an error and the `PortMapping` back.
    /// # Errors
    /// Returns a pair containing a `pcp::Failure` enum, which decomposes into different errors
    /// depending on the cause, and the unmodified mapping.
    pub async fn try_drop(self) -> Result<(), (Failure, Self)> {
        // Attempt to drop the existing port mapping on the gateway.
        try_drop_mapping(
            self.gateway,
            self.client,
            self.nonce,
            DropMappingRange::All {
                protocol: self.protocol,
            },
            Some(self.timeout_config),
        )
        .await
        .map_err(|e| (e, self))
    }

    #[must_use]
    pub fn gateway(&self) -> IpAddr {
        self.gateway
    }
    #[must_use]
    pub fn client(&self) -> IpAddr {
        self.client
    }
    #[must_use]
    pub fn protocol(&self) -> Option<InternetProtocol> {
        self.protocol
    }
    #[must_use]
    pub fn external_ip(&self) -> IpAddr {
        self.external_ip
    }
    #[must_use]
    pub fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }
    #[must_use]
    pub fn gateway_epoch_seconds(&self) -> u32 {
        self.gateway_epoch_seconds
    }
    #[must_use]
    pub fn nonce(&self) -> Nonce {
        self.nonce
    }
    #[must_use]
    pub fn expiration(&self) -> std::time::Instant {
        self.expiration
    }
}

#[cfg(test)]
mod tests;
