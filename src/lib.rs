//! # 🦀 NAT

//! A library providing a pure Rust implementation of a client for both the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)) and the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)).

//! This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asyncronous, and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and succinctly handle timeouts on UDP sockets.

//! ## Usage
//! ```rust,no_run
//! async {
//!     // Attempt a port mapping request through PCP first and fallback to NAT-PMP.
//!     let mapping = match crab_nat::try_port_mapping(
//!         std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)) /* address of the PCP server, often a gateway or firewall */,
//!         std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 167)) /* address of our client, as seen by the gateway. Only used by PCP */,
//!         crab_nat::InternetProtocol::Tcp,
//!         8080 /* internal port */,
//!         None /* external port, no preference */,
//!         None /* lifetime, use default of 2 hours */,
//!     )
//!     .await
//!     {
//!         Ok(m) => m,
//!         Err(e) => return eprintln!("Failed to map port: {e:?}"),
//!     };
//! };
//! ```

use std::{net::IpAddr, time::Duration};

use num_enum::TryFromPrimitive;

pub mod natpmp;
pub mod pcp;

/// 8-bit version field in the NAT-PMP and PCP headers.
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum Version {
    /// NAT-PMP identifies its version with a `0` byte.
    NatPmp = 0,

    /// PCP identifies its version with a `2` byte.
    /// The RFC explicitly states that PCP must use version `2` because non-compliant
    /// devices were created that used `1` before the creation of PCP.
    Pcp = 2,
}

/// Specifies the protocol to map a port for.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum InternetProtocol {
    Udp = 1,
    Tcp,
}

/// A port mapping on the gateway.
pub struct PortMapping {
    pub gateway: IpAddr,
    pub protocol: InternetProtocol,
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime: Duration,
    pub version: Version,
}

// The RFC states that connections SHOULD make up to 9 attempts <https://www.rfc-editor.org/rfc/rfc6886#section-3.1>, but we will only make 4 attempts.
const SANE_MAX_REQUEST_RETRIES: usize = 3;

/// The required port for NAT-PMP and its successor, PCP.
pub const GATEWAY_PORT: u16 = 5351;

/// Attempts to map a port on the gateway using PCP first and falling back to NAT-PMP.
/// Will request to use a given external port if specified, otherwise it will let the gateway choose.
/// If no lifetime is specified, the NAT-PMP recommended lifetime of two hours will be used.
/// # Notes
/// * A lifetime of `0` will request the gateway to delete the port mapping immediately.
///   * This can be paired with a local port of `0` to delete all mappings for the protocol.
/// # Errors
/// May fail from issues encountered by the UDP socket, the gateway not responding, or the gateway giving an invalid response.
pub async fn try_port_mapping(
    gateway: IpAddr,
    client: IpAddr,
    protocol: InternetProtocol,
    internal_port: u16,
    external_port: Option<u16>,
    lifetime_seconds: Option<u32>,
) -> Result<PortMapping, MappingFailure> {
    // Try to use the more modern protocol, PCP, first.
    match pcp::try_port_mapping(
        gateway,
        client,
        protocol,
        internal_port,
        external_port,
        lifetime_seconds.unwrap_or(natpmp::RECOMMENDED_MAPPING_LIFETIME_SECONDS),
    )
    .await
    {
        Ok(m) => return Ok(m),
        Err(e) => eprintln!("Failed to map port using PCP: {e:#}"),
    }

    // Fall back to the older, possibly more widely supported, NAT-PMP.
    natpmp::try_port_mapping(gateway, protocol, internal_port, external_port, None)
        .await
        .map_err(std::convert::Into::into)
}

/// Private module for shared helper functions within the library.
mod helpers {
    use std::time::Duration;

    use tokio::net::UdpSocket;

    /// Create a new UDP socket and connect it to the gateway socket address for NAT-PMP or PCP.
    /// # Errors
    /// Will return an error if we fail to bind to a local UDP socket or connect to the gateway address.
    pub async fn new_socket(
        gateway: std::net::IpAddr,
    ) -> Result<tokio::net::UdpSocket, std::io::Error> {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

        // Create a new UDP with an IP protocol matching that of the gateway address.
        let socket = tokio::net::UdpSocket::bind(if gateway.is_ipv4() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        } else {
            // The Rust standard library uses `0` as the `flowinfo` and `scope_id` for an `Ipv6Addr` created from an address and port number.
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        })
        .await?;
        socket.connect((gateway, crate::GATEWAY_PORT)).await?;

        Ok(socket)
    }

    pub enum RequestSendError {
        Socket(std::io::Error),
        Timeout(),
    }

    /// Send a request and wait for a response, retrying on timeout up to `max_retries` times.
    /// # Errors
    /// Will return an error if we:
    /// * Fail to send the request
    /// * Fail to receive a response within the timeouts and retries
    /// * If there is a network error on receiving the response
    pub async fn try_send_until_response(
        max_retries: usize,
        initial_timeout: Duration,
        socket: &UdpSocket,
        send_bytes: &[u8],
        recv_buf: &mut bytes::BytesMut,
    ) -> Result<usize, RequestSendError> {
        // Create an internal helper to easily try sending and receiving packets, and springboard errors back to the caller.
        async fn send_and_recv(
            socket: &UdpSocket,
            send_bytes: &[u8],
            recv_buf: &mut bytes::BytesMut,
            timeout: Duration,
        ) -> Result<usize, RequestSendError> {
            socket
                .send(send_bytes)
                .await
                .map_err(RequestSendError::Socket)?;

            tokio::time::timeout(timeout, socket.recv_buf(recv_buf))
                .await
                .map_err(|_| RequestSendError::Timeout())?
                .map_err(RequestSendError::Socket)
        }

        // Use the RFC recommended initial timeout and double it on each successive failure.
        let mut wait = initial_timeout;
        let mut retries = 0;
        loop {
            match send_and_recv(socket, send_bytes, recv_buf, wait).await {
                // Return the number of bytes read from the response.
                Ok(n) => return Ok(n),

                // Retry on timeout up to `max_retries` times.
                Err(RequestSendError::Timeout()) => {
                    if retries >= max_retries {
                        return Err(RequestSendError::Timeout());
                    }
                    retries += 1;

                    // Follow RFC recommendation to double the timeout on each successive failure.
                    // TODO: PCP Requires a random value in [0.9, 1.1] be multiplied by the timeout.
                    wait += wait;

                    #[cfg(debug_assertions)]
                    println!("Retrying with timeout {wait:?}: {retries}/{max_retries} retries");
                }

                // Any other error is returned immediately.
                Err(e) => return Err(e),
            }
        }
    }
}

/// Errors that occur during the respective port mapping protocols.
#[derive(Debug)]
pub enum MappingFailure {
    NatPmp(natpmp::Failure),
    Pcp(pcp::Failure),
}
impl From<natpmp::Failure> for MappingFailure {
    fn from(f: natpmp::Failure) -> Self {
        MappingFailure::NatPmp(f)
    }
}
impl From<pcp::Failure> for MappingFailure {
    fn from(f: pcp::Failure) -> Self {
        MappingFailure::Pcp(f)
    }
}
