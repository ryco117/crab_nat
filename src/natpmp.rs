use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use bytes::{Buf, BufMut};
use num_enum::TryFromPrimitive;

use crate::{
    helpers::{self, RequestSendError},
    InternetProtocol, PortMapping, PortMappingOptions, PortMappingType, TimeoutConfig, VersionCode,
    RECOMMENDED_MAPPING_LIFETIME_SECONDS, SANE_MAX_REQUEST_RETRIES,
};

/// The RFC states that the first response timeout SHOULD be 250 milliseconds, and double on each successive failure.
pub const FIRST_TIMEOUT_MILLIS: u64 = 250;

/// NAT-PMP does not require datagrams larger than 16 bytes.
pub const MAX_DATAGRAM_SIZE: usize = 16;

/// The default `TimeoutConfig` for NAT-PMP requests.
const TIMEOUT_CONFIG_DEFAULT: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_millis(FIRST_TIMEOUT_MILLIS),
    max_retries: SANE_MAX_REQUEST_RETRIES,
    max_retry_timeout: None,
};

/// Result codes from a NAT-PMP response.
/// See <https://www.rfc-editor.org/rfc/rfc6886#section-3.5>
#[derive(Debug, displaydoc::Display, PartialEq, thiserror::Error, TryFromPrimitive)]
#[repr(u16)]
pub enum ResultCode {
    /// Success. Will not be returned as an error.
    Success,

    /// The server does not support this version of the protocol.
    UnsupportedVersion,

    /// The server did not authorize the operation.
    NotAuthorized,

    /// The server is not in a valid network state to perform the operation.
    NetworkFailure,

    /// The server is lacking resources, such as open ports, to complete the operation.
    OutOfResources,

    /// The server does not support the requested operation.
    UnsupportedOpcode,
}

/// Operation codes for NAT-PMP.
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum OperationCode {
    /// Request the public IP address of the gateway.
    ExternalAddress,
    /// Map a UDP port on the gateway.
    MapUdp,
    /// Map a TCP port on the gateway.
    MapTcp,
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

/// Attempt to complete the `ExternalAddress` operation.
/// Returns the public IP address of the gateway.
/// # Errors
/// Returns a `natpmp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_external_address(
    gateway: IpAddr,
    timeout_config: Option<TimeoutConfig>,
) -> Result<Ipv4Addr, Failure> {
    // Create a new UDP socket and connect to the gateway.
    let socket = helpers::new_socket(gateway)
        .await
        .map_err(Failure::Socket)?;

    // Use a byte-buffer to read the response into.
    let mut reader = bytes::BytesMut::with_capacity(MAX_DATAGRAM_SIZE);
    // Try to send the request data until a response is read, respecting the RFC recommended timeouts and retries counts.
    let n = helpers::try_send_until_response(
        timeout_config.unwrap_or(TIMEOUT_CONFIG_DEFAULT),
        &socket,
        &[
            VersionCode::NatPmp as u8,
            OperationCode::ExternalAddress as u8,
        ],
        &mut reader,
    )
    .await?;

    // An `ExternalAddress` response is always expected to be 12 bytes.
    if n != 12 {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect number of bytes: {n}"
        )));
    }

    // Read and verify the version and operation bytes.
    let v = VersionCode::try_from(reader.get_u8())
        .map_err(|v| Failure::InvalidResponse(format!("Invalid version: {v:#}")))?;
    let op = response_to_opcode(reader.get_u8())
        .map_err(|o| Failure::InvalidResponse(format!("Invalid operation code: {o:#}")))?;
    if v != VersionCode::NatPmp {
        return Err(Failure::InvalidResponse(format!(
            "Unsupported version: {v:?}"
        )));
    }
    if op != OperationCode::ExternalAddress {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect opcode: {op:?}"
        )));
    }

    // Read and verify the result code. Also, optionally print the gateway epoch.
    let result_code = ResultCode::try_from(reader.get_u16())
        .map_err(|r| Failure::InvalidResponse(format!("Invalid result code: {r:#}")))?;
    let gateway_epoch = Duration::from_secs(u64::from(reader.get_u32()));
    #[cfg(debug_assertions)]
    println!("DEBUG Gateway epoch was {gateway_epoch:?} ago");

    if result_code != ResultCode::Success {
        // The server gave us a correct response, but it was an error.
        return Err(Failure::ResultCode(result_code));
    }

    // The response was a success, read the remaining 4 bytes as the external IP.
    let external_ip = Ipv4Addr::new(
        reader.get_u8(),
        reader.get_u8(),
        reader.get_u8(),
        reader.get_u8(),
    );

    #[cfg(debug_assertions)]
    println!("DEBUG Gateway external IP: {external_ip:#}");

    Ok(external_ip)
}

/// Attempts to map a port on the gateway using NAT-PMP.
/// Will try to use the given external port if it is `Some`, otherwise it will let the gateway choose.
/// Will request the specified lifetime if it is `Some`, otherwise it will use the RFC recommended lifetime.
/// # Errors
/// Returns a `natpmp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_port_mapping(
    gateway: IpAddr,
    protocol: InternetProtocol,
    internal_port: u16,
    mapping_options: PortMappingOptions,
) -> Result<PortMapping, Failure> {
    let socket = helpers::new_socket(gateway)
        .await
        .map_err(Failure::Socket)?;

    // Determine the operation code based on the protocol to map.
    let req_op = match protocol {
        InternetProtocol::Udp => OperationCode::MapUdp,
        InternetProtocol::Tcp => OperationCode::MapTcp,
    };

    // Create a byte-buffer with enough space for the request and response bytes.
    let mut bb = bytes::BytesMut::with_capacity(MAX_DATAGRAM_SIZE << 1);

    // Format the port mapping request.
    bb.put_u8(VersionCode::NatPmp as u8);
    bb.put_u8(req_op as u8);
    bb.put_u16(0); // Reserved.
    bb.put_u16(internal_port);
    bb.put_u16(mapping_options.external_port.unwrap_or_default());
    bb.put_u32(
        mapping_options
            .lifetime_seconds
            .unwrap_or(RECOMMENDED_MAPPING_LIFETIME_SECONDS),
    );

    // Split the byte buffer into a send buffer and a receive buffer.
    let send_buf = bb.split();

    let timeout_config = mapping_options
        .timeout_config
        .unwrap_or(TIMEOUT_CONFIG_DEFAULT);

    // Try to send the request data until a response is read, respecting the RFC recommended timeouts and retries counts.
    let n = helpers::try_send_until_response(timeout_config, &socket, &send_buf, &mut bb).await?;

    // A port mapping response is always expected to be 16 bytes.
    if n != 16 {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect number of bytes: {n}"
        )));
    }

    // Read and verify the version and operation bytes.
    let v = VersionCode::try_from(bb.get_u8())
        .map_err(|v| Failure::InvalidResponse(format!("Invalid version: {v:#}")))?;
    let op = response_to_opcode(bb.get_u8())
        .map_err(|o| Failure::InvalidResponse(format!("Invalid operation code: {o:#}")))?;
    if v != VersionCode::NatPmp {
        return Err(Failure::InvalidResponse(format!(
            "Unsupported version: {v:?}"
        )));
    }
    let protocol = match (op, op == req_op) {
        (OperationCode::MapUdp, true) => InternetProtocol::Udp,
        (OperationCode::MapTcp, true) => InternetProtocol::Tcp,
        _ => {
            return Err(Failure::InvalidResponse(format!(
                "Incorrect opcode: {op:?}"
            )))
        }
    };

    // Read and verify the result code. Also, optionally print the gateway epoch.
    let response_code = ResultCode::try_from(bb.get_u16())
        .map_err(|r| Failure::InvalidResponse(format!("Invalid result code: {r:#}")))?;
    let gateway_epoch = Duration::from_secs(u64::from(bb.get_u32()));

    #[cfg(debug_assertions)]
    println!("DEBUG Gateway epoch was {gateway_epoch:?} ago");

    if response_code != ResultCode::Success {
        // The server gave us a correct response, but it was an error.
        return Err(Failure::ResultCode(response_code));
    }

    // The response was a success, read the mapping information.
    let internal_port = bb.get_u16();
    let external_port = bb.get_u16();
    let lifetime_seconds = bb.get_u32();

    Ok(PortMapping {
        gateway,
        protocol,
        internal_port,
        external_port,
        lifetime_seconds,
        expiration: std::time::Instant::now() + Duration::from_secs(u64::from(lifetime_seconds)),
        mapping_type: PortMappingType::NatPmp,
        timeout_config,
    })
}

/// Attempts to remove a NAT-PMP mapping on the gateway.
/// Using a local port of `0` will remove all port mappings for our client with the given protocol.
/// # Errors
/// Returns a `natpmp::Failure` enum which decomposes into different errors depending on the cause:
/// * `Socket` if there is an error using the UDP socket
/// * `Timeout` if the gateway is not responding
/// * `InvalidResponse` if the gateway gave an invalid response
/// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
pub async fn try_drop_mapping(
    gateway: IpAddr,
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
        protocol,
        local_port,
        PortMappingOptions {
            external_port: Some(0),
            lifetime_seconds: Some(0),
            timeout_config,
        },
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

/// Response `OperationCode`s are the same as the request `OperationCode`s, but with the 128 bit set.
/// This function subtracts the `128` from the response code and returns the result.
fn response_to_opcode(
    op: u8,
) -> Result<OperationCode, num_enum::TryFromPrimitiveError<OperationCode>> {
    OperationCode::try_from(op - 128)
}
