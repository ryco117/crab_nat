use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use bytes::{Buf, BufMut};
use num_enum::TryFromPrimitive;

use crate::{helpers, InternetProtocol, PortMapping, Version, SANE_MAX_DATAGRAM_SIZE};

/// The RFC recommended lifetime for a port mapping.
pub const RECOMMENDED_MAPPING_LIFETIME_SECONDS: u32 = 7200;

/// Result codes from a NAT-PMP response.
/// See <https://www.rfc-editor.org/rfc/rfc6886#section-3.5>
#[derive(Debug, displaydoc::Display, PartialEq, thiserror::Error, TryFromPrimitive)]
#[repr(u16)]
pub enum ResultCode {
    /// Success. Will not be returned as an error.
    Success,
    /// The server does not support this version of the protocol.
    UnsupportedVersion,
    /// The server did not grant us permission to perform the operation.
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
pub enum Failure {
    /// Failed to bind, connect, read, or write to a UDP socket.
    #[error("UDP socket error: {0}")]
    Socket(std::io::Error),

    /// The gateway was unreachable within the timeout.
    #[error("Gateway did not respond within the timeout")]
    Timeout(()),

    /// The gateway did not give a valid response according to the NAT-PMP protocol.
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// The gateway gave a valid response, but it was an error.
    /// The `ResultCode` is guaranteed to not be `ResultCode::Success`.
    #[error("Gateway error: {0}")]
    ResultCode(ResultCode),
}

/// Attempt to complete the `ExternalAddress` operation.
/// Returns the public IP address of the gateway.
/// # Errors
/// Will return an error if we fail to bind to a local UDP socket, fail to send the request, or fail to receive a valid response.
pub async fn try_external_address(gateway: IpAddr) -> Result<Ipv4Addr, Failure> {
    // Create a new UDP socket and connect to the gateway.
    let socket = helpers::new_socket(gateway)
        .await
        .map_err(Failure::Socket)?;

    // Get external address.
    socket
        .send(&[Version::NatPmp as u8, OperationCode::ExternalAddress as u8])
        .await
        .map_err(Failure::Socket)?;

    let mut reader = bytes::BytesMut::with_capacity(SANE_MAX_DATAGRAM_SIZE);

    // TODO: Wrap send  and response in a loop that retries on timeout.
    let n = tokio::time::timeout(
        Duration::from_millis(crate::FIRST_TIMEOUT_MILLIS),
        socket.recv_buf(&mut reader),
    )
    .await
    .map_err(|_| Failure::Timeout(()))?
    .map_err(Failure::Socket)?;

    // An `ExternalAddress` response is always expected to be 12 bytes.
    if n != 12 {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect number of bytes: {n}"
        )));
    }

    // Read and verify the version and operation bytes.
    let v = Version::try_from(reader.get_u8())
        .map_err(|v| Failure::InvalidResponse(format!("Invalid version: {v:#}")))?;
    let op = OperationCode::try_from(response_to_opcode(reader.get_u8()))
        .map_err(|o| Failure::InvalidResponse(format!("Invalid operation code: {o:#}")))?;
    if v != Version::NatPmp {
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
    let response_code = ResultCode::try_from(reader.get_u16())
        .map_err(|r| Failure::InvalidResponse(format!("Invalid result code: {r:#}")))?;
    let gateway_epoch = Duration::from_secs(u64::from(reader.get_u32()));
    #[cfg(debug_assertions)]
    println!("Gateway epoch was {gateway_epoch:?} ago");
    if response_code != ResultCode::Success {
        // The server gave us a correct response, but it was an error.
        return Err(Failure::ResultCode(response_code));
    }

    // The response was a success, read the remaining 4 bytes as the external IP.
    let external_ip = Ipv4Addr::new(
        reader.get_u8(),
        reader.get_u8(),
        reader.get_u8(),
        reader.get_u8(),
    );

    #[cfg(debug_assertions)]
    println!("Gateway external IP: {external_ip:#}");

    Ok(external_ip)
}

/// Attempts to map a port on the gateway using NAT-PMP or PCP.
/// Will try to use the given external port if it is `Some`, otherwise it will let the gateway choose.
/// # Errors
/// Returns a `natpmp::Failure` enum which decomposes into the following errors:
pub async fn try_port_mapping(
    gateway: IpAddr,
    protocol: InternetProtocol,
    internal_port: u16,
    external_port: Option<u16>,
) -> Result<PortMapping, Failure> {
    let socket = helpers::new_socket(gateway)
        .await
        .map_err(Failure::Socket)?;

    // Determine the operation code based on the protocol to map.
    let req_op = match protocol {
        InternetProtocol::Udp => OperationCode::MapUdp,
        InternetProtocol::Tcp => OperationCode::MapTcp,
    };

    // Format the port mapping request.
    let mut bb = bytes::BytesMut::with_capacity(SANE_MAX_DATAGRAM_SIZE);
    bb.put_u8(Version::NatPmp as u8);
    bb.put_u8(req_op as u8);
    bb.put_u16(0); // Reserved.
    bb.put_u16(internal_port);
    bb.put_u16(external_port.unwrap_or_default());
    bb.put_u32(RECOMMENDED_MAPPING_LIFETIME_SECONDS);

    // Send the request.
    socket.send(&bb).await.map_err(Failure::Socket)?;

    // Clear the byte buffer before using it to read the response.
    bb.clear();

    // TODO: Wrap send  and response in a loop that retries on timeout.
    let n = tokio::time::timeout(
        Duration::from_millis(crate::FIRST_TIMEOUT_MILLIS),
        socket.recv_buf(&mut bb),
    )
    .await
    .map_err(|_| Failure::Timeout(()))?
    .map_err(Failure::Socket)?;

    // A port mapping response is always expected to be 12 bytes.
    if n != 16 {
        return Err(Failure::InvalidResponse(format!(
            "Incorrect number of bytes: {n}"
        )));
    }

    // Read and verify the version and operation bytes.
    let v = Version::try_from(bb.get_u8())
        .map_err(|v| Failure::InvalidResponse(format!("Invalid version: {v:#}")))?;
    let op = OperationCode::try_from(response_to_opcode(bb.get_u8()))
        .map_err(|o| Failure::InvalidResponse(format!("Invalid operation code: {o:#}")))?;
    if v != Version::NatPmp {
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
    println!("Gateway epoch was {gateway_epoch:?} ago");
    if response_code != ResultCode::Success {
        // The server gave us a correct response, but it was an error.
        return Err(Failure::ResultCode(response_code));
    }

    // The response was a success, read the mapping information.
    let internal_port = bb.get_u16();
    let external_port = bb.get_u16();
    let lifetime = Duration::from_secs(u64::from(bb.get_u32()));

    Ok(PortMapping {
        gateway,
        protocol,
        internal_port,
        external_port,
        lifetime,
        version: v,
    })
}

/// Response `OpCodes` are the same as the request `OpCodes`, but with the 128 bit set.
/// This function subtracts the `128` from the response code and returns the result.
fn response_to_opcode(op: u8) -> u8 {
    op - 128
}
