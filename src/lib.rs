//! # 🦀 NAT

//! A library providing a pure Rust implementation of a client for both the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)) and the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)).

//! This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asyncronous, and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and succinctly handle timeouts on UDP sockets.

//! ## Usage
//! ```rust,no_run
//! async {
//!     // Attempt a port mapping request through PCP first and fallback to NAT-PMP.
//!     let mapping = match crab_nat::PortMapping::new(
//!         std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)) /* Address of the PCP server, often a gateway or firewall */,
//!         std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 167)) /* Address of our client, as seen by the gateway. Only used by PCP */,
//!         crab_nat::InternetProtocol::Tcp /* Protocol to map */,
//!         std::num::NonZeroU16::new(8080).unwrap() /* Internal port, cannot be zero */,
//!         PortMappingOptions::Default() /* Optional configuration values, including suggested external port and lifetimes */,
//!     )
//!     .await
//!     {
//!         Ok(m) => m,
//!         Err(e) => return eprintln!("Failed to map port: {e:?}"),
//!     };
//!
//!     // ...
//!
//!     // Try to safely drop the mapping.
//!     if let Err((e, m)) = mapping.try_drop().await {
//!         eprintln!("Failed to drop mapping {}:{}->{}: {e:?}", m.gateway(), m.external_port(), m.internal_port());
//!     } else {
//!         println!("Successfully deleted the mapping...");
//!     }
//! };
//! ```

use std::net::IpAddr;

use num_enum::TryFromPrimitive;

pub mod natpmp;
pub mod pcp;

// The RFC for NAT-PMP states that connections SHOULD make up to 9 attempts, <https://www.rfc-editor.org/rfc/rfc6886#section-3.1> page 6.
// The RFC for PCP states that connections SHOULD make attempts without a limit, <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1> page 22.
// However, that would be largely impractical so we set a sane default of 3 retries after an initial timeout fails.
const SANE_MAX_REQUEST_RETRIES: usize = 3;

/// The required port for NAT-PMP and its successor, PCP.
pub const GATEWAY_PORT: u16 = 5351;

/// The RFC recommended lifetime for a port mapping, <https://www.rfc-editor.org/rfc/rfc6886#section-3.3> page 12.
pub const RECOMMENDED_MAPPING_LIFETIME_SECONDS: u32 = 7200;

/// 8-bit version field in the NAT-PMP and PCP headers.
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum VersionCode {
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

/// Specifies a port mapping protocol, as well as any protocol specific parameters.
#[derive(Clone, Copy, Debug)]
pub enum PortMappingType {
    NatPmp,
    Pcp { client: IpAddr },
}

/// Configuration of the timing of UDP requests to the gateway.
#[derive(Clone, Copy)]
pub struct TimeoutConfig {
    /// The initial timeout for the first request. In general, the timeout will be doubled on each successive retry.
    pub initial_timeout: std::time::Duration,
    /// The maximum number of retries to attempt before giving up.
    /// Note that the first request is not considered a retry.
    pub max_retries: usize,
    /// The maximum timeout to use for a retry.
    pub max_retry_timeout: Option<std::time::Duration>,
}

/// Optional configuration values for a port mapping request.
#[derive(Clone, Copy, Default)]
pub struct PortMappingOptions {
    /// The external port to try to map. The server is not guaranteed to use this port.
    pub external_port: Option<u16>,
    /// The lifetime of the port mapping in seconds. The server is not guaranteed to use this lifetime.
    pub lifetime_seconds: Option<u32>,
    /// The configuration of the timing of UDP requests made to the gateway.
    pub timeout_config: Option<TimeoutConfig>,
}

/// A port mapping on the gateway. Should be renewed with `.try_renew()` and deleted from the gateway with `.try_drop()`.
pub struct PortMapping {
    /// The address of the gateway the mapping is registered with.
    gateway: IpAddr,
    /// The protocol the mapping is for.
    protocol: InternetProtocol,
    /// The internal/local port of the port mapping.
    internal_port: u16,
    /// The external port of the port mapping.
    external_port: u16,
    /// The lifetime of the port mapping in seconds.
    lifetime_seconds: u32,
    /// The datetime the port mapping is set to expire at.
    expiration: std::time::Instant,
    /// The type of mapping protocol used, as well as any protocol specific parameters.
    mapping_type: PortMappingType,
    /// The configuration of the timing of UDP requests made to the gateway.
    pub timeout_config: TimeoutConfig,
}
impl PortMapping {
    /// Attempts to map a port on the gateway using PCP first and falling back to NAT-PMP.
    /// Will request to use the given external port if specified, otherwise it will let the gateway choose.
    /// If no lifetime is specified, the NAT-PMP recommended lifetime of two hours will be used.
    /// # Errors
    /// Returns a `MappingFailure` enum which decomposes into different errors depending on the cause:
    /// * `Socket` if there is an error using the UDP socket
    /// * `Timeout` if the gateway is not responding
    /// * `InvalidResponse` if the gateway gave an invalid response
    /// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
    pub async fn new(
        gateway: IpAddr,
        client: IpAddr,
        protocol: InternetProtocol,
        internal_port: std::num::NonZeroU16,
        mapping_options: PortMappingOptions,
    ) -> Result<PortMapping, MappingFailure> {
        // Try to use the more modern protocol, PCP, first.
        match pcp::try_port_mapping(
            gateway,
            client,
            protocol,
            internal_port.get(),
            mapping_options,
        )
        .await
        {
            Ok(m) => return Ok(m),
            Err(pcp::Failure::ResultCode(pcp::ResultCode::UnsupportedVersion)) => {}
            Err(e) => eprintln!("Failed to map port using PCP: {e:#}"),
        }

        // Fall back to the older, possibly more widely supported, NAT-PMP.
        natpmp::try_port_mapping(gateway, protocol, internal_port.get(), mapping_options)
            .await
            .map_err(std::convert::Into::into)
    }

    /// Attempts to renew this port mapping on the gateway, otherwise returns an error.
    /// # Errors
    /// Returns a `MappingFailure` enum which decomposes into different errors depending on the cause:
    /// * `Socket` if there is an error using the UDP socket
    /// * `Timeout` if the gateway is not responding
    /// * `InvalidResponse` if the gateway gave an invalid response
    /// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
    pub async fn try_renew(&mut self) -> Result<(), MappingFailure> {
        // The optional configuration values for the port mapping request.
        let options = PortMappingOptions {
            external_port: Some(self.external_port),
            lifetime_seconds: Some(self.lifetime()),
            timeout_config: Some(self.timeout_config),
        };

        // Attempt to renew the existing port mapping on the gateway.
        match self.mapping_type {
            PortMappingType::NatPmp => {
                *self = natpmp::try_port_mapping(
                    self.gateway,
                    self.protocol,
                    self.internal_port,
                    options,
                )
                .await
                .map_err(MappingFailure::from)?;
            }
            PortMappingType::Pcp { client } => {
                *self = pcp::try_port_mapping(
                    self.gateway,
                    client,
                    self.protocol,
                    self.internal_port,
                    options,
                )
                .await
                .map_err(MappingFailure::from)?;
            }
        }
        Ok(())
    }

    /// Attempts to safely delete this port mapping on the gateway, otherwise returns an error and the `PortMapping` back.
    /// # Errors
    /// Returns a `MappingFailure` enum which decomposes into different errors depending on the cause:
    /// * `Socket` if there is an error using the UDP socket
    /// * `Timeout` if the gateway is not responding
    /// * `InvalidResponse` if the gateway gave an invalid response
    /// * `ResultCode` if the gateway gave a valid response, but it was an error. Will never return `ResultCode::Success` as an error.
    pub async fn try_drop(self) -> Result<(), (MappingFailure, Self)> {
        let gateway = self.gateway();
        let protocol = self.protocol();
        let internal_port = self.internal_port();
        let mapping_type = self.mapping_type();

        // Attempt to delete the port mapping on the gateway.
        match mapping_type {
            PortMappingType::NatPmp => natpmp::try_drop_mapping(
                self.gateway(),
                self.protocol(),
                internal_port,
                Some(self.timeout_config),
            )
            .await
            .map_err(|e| (MappingFailure::from(e), self)),
            PortMappingType::Pcp { client } => pcp::try_drop_mapping(
                gateway,
                client,
                protocol,
                internal_port,
                Some(self.timeout_config),
            )
            .await
            .map_err(|e| (MappingFailure::from(e), self)),
        }
    }

    #[must_use]
    pub fn gateway(&self) -> IpAddr {
        self.gateway
    }
    #[must_use]
    pub fn protocol(&self) -> InternetProtocol {
        self.protocol
    }
    #[must_use]
    pub fn internal_port(&self) -> u16 {
        self.internal_port
    }
    #[must_use]
    pub fn external_port(&self) -> u16 {
        self.external_port
    }
    #[must_use]
    pub fn lifetime(&self) -> u32 {
        self.lifetime_seconds
    }
    #[must_use]
    pub fn expiration(&self) -> std::time::Instant {
        self.expiration
    }
    #[must_use]
    pub fn mapping_type(&self) -> PortMappingType {
        self.mapping_type
    }
}

/// Private module for shared helper functions within the library.
mod helpers {
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use crate::TimeoutConfig;

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
        Timeout,
    }

    /// Send a request and wait for a response, retrying on timeout up to `max_retries` times.
    /// # Errors
    /// Will return a `Socket(..)` error if we:
    /// * Failed to send data on the socket
    /// * Failed to receive data on the socket
    /// Otherwise, will return a `Timeout` error if the gateway could not be reached after all retries.
    pub async fn try_send_until_response(
        timeout_config: TimeoutConfig,
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
                .map_err(|_| RequestSendError::Timeout)?
                .map_err(RequestSendError::Socket)
        }

        // Use the RFC recommended initial timeout and double it on each successive failure.
        let mut wait = timeout_config.initial_timeout;
        let mut retries = 0;
        loop {
            match send_and_recv(socket, send_bytes, recv_buf, wait).await {
                // Return the number of bytes read from the response.
                Ok(n) => return Ok(n),

                // Retry on timeout up to `max_retries` times.
                Err(RequestSendError::Timeout) => {
                    if retries >= timeout_config.max_retries {
                        return Err(RequestSendError::Timeout);
                    }
                    retries += 1;

                    // Follow RFC recommendation to double the timeout on each successive failure.
                    // TODO: PCP Requires a random value in [0.9, 1.1] be multiplied by the timeout.
                    wait += wait;

                    // Limit the timeout to the configured maximum.
                    if let Some(max) = timeout_config.max_retry_timeout {
                        if wait > max {
                            wait = max;
                        }
                    }

                    #[cfg(debug_assertions)]
                    println!(
                        "DEBUG Starting retry {retries}/{} with timeout {wait:?}",
                        timeout_config.max_retries
                    );
                }

                // Any other error is returned immediately.
                Err(e) => return Err(e),
            }
        }
    }
}

/// Errors that occur during the respective port mapping protocols.
#[derive(Debug, thiserror::Error)]
pub enum MappingFailure {
    #[error("NAT-PMP({0})")]
    NatPmp(natpmp::Failure),
    #[error("PCP({0})")]
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
