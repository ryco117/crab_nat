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
#[derive(Debug)]
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

/// Attempts to map a port on the gateway using NAT-PMP.
/// Will try to use the given external port if it is `Some`, otherwise it will let the gateway choose.
/// # Errors
/// May fail from issues encountered by the UDP socket, the gateway not responding, or the gateway giving an invalid response.
pub async fn try_port_mapping(
    gateway: IpAddr,
    protocol: InternetProtocol,
    internal_port: u16,
    external_port: Option<u16>,
) -> anyhow::Result<PortMapping> {
    natpmp::try_port_mapping(gateway, protocol, internal_port, external_port, None)
        .await
        .map_err(std::convert::Into::into)
}

mod helpers {
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
}
