use std::{net::IpAddr, num::NonZeroU16};

use crab_nat::PortMappingOptions;

#[derive(clap::Parser)]
struct Cli {
    /// Delete the port mapping instead of creating one.
    #[arg(short, long, default_value_t = false)]
    delete: bool,

    /// The gateway address to use. If empty, will attempt to determine the default gateway.
    #[arg(short, long, default_value = "")]
    gateway: String,

    /// The local address the gateway will expect to see our address as. If empty, will attempt to use the default local address.
    #[arg(short, long, default_value = "")]
    local_address: String,

    /// The internal port to map into.
    #[arg(short = 'p', long, default_value_t = 8080)]
    internal_port: u16,

    /// The external port to try to map. Server is not guaranteed to use this port.
    #[arg(short = 'e', long)]
    external_port: Option<NonZeroU16>,

    /// Fetch the external IP address through NAT-PMP and exit.
    #[arg(short = 'x', long)]
    external_ip: bool,

    /// The protocol to map.
    #[arg(short, long, default_value = "tcp")]
    internet_protocol: String,
}

#[tokio::main]
async fn main() {
    use clap::Parser as _;
    let args = Cli::parse();

    // Initialize the default logger. This is optional to use the crate and currently only shows UDP retry attempts.
    tracing_subscriber::fmt::init();

    // Get the protocol from the command line or use the default.
    let protocol = match args.internet_protocol.to_lowercase().as_str().trim() {
        "udp" => crab_nat::InternetProtocol::Udp,
        "tcp" => crab_nat::InternetProtocol::Tcp,
        _ => panic!("Invalid protocol"),
    };

    let local_address = if args.local_address.is_empty() {
        netdev::interface::get_local_ipaddr().expect("Could not determine a local address")
    } else {
        args.local_address
            .parse()
            .expect("Invalid local address format")
    };
    tracing::info!("Using local address: {local_address:#}");

    // Get the gateway address from the command line or guess the default.
    let gateway = if args.gateway.is_empty() {
        let gateway = netdev::get_default_gateway().expect("Could not determine a gateway");
        if local_address.is_ipv4() {
            gateway
                .ipv4
                .first()
                .map(|ip| IpAddr::V4(*ip))
                .unwrap_or_else(|| {
                    IpAddr::V6(
                        *gateway
                            .ipv6
                            .first()
                            .expect("No addresses found for default gateway"),
                    )
                })
        } else {
            gateway
                .ipv6
                .first()
                .map(|ip| IpAddr::V6(*ip))
                .unwrap_or_else(|| {
                    IpAddr::V4(
                        *gateway
                            .ipv4
                            .first()
                            .expect("No addresses found for default gateway"),
                    )
                })
        }
    } else {
        args.gateway.parse().expect("Invalid gateway format")
    };
    tracing::info!("Using gateway address: {gateway:#}");

    // If the external IP flag is set, attempt to get the external IP and exit.
    if args.external_ip {
        let external_ip = match crab_nat::natpmp::try_external_address(gateway, None).await {
            Ok(ip) => ip,
            Err(e) => return tracing::error!("Failed to get external IP: {e:#}"),
        };
        return tracing::info!("External IP: {external_ip:#}");
    }

    if args.delete {
        // Attempt a port unmapping request.
        if let Err(e) = crab_nat::natpmp::try_drop_mapping(
            gateway,
            protocol,
            NonZeroU16::new(args.internal_port),
            None,
        )
        .await
        {
            return tracing::error!("Failed to unmap port: {e:#}");
        }

        // Print the mapped port information.
        tracing::info!("Success! Deleted previous port mapping");
    } else {
        // Attempt a port mapping request.
        let mapping = match crab_nat::PortMapping::new(
            gateway,
            local_address,
            protocol,
            NonZeroU16::new(args.internal_port).expect("Invalid internal port"),
            PortMappingOptions {
                external_port: args.external_port,
                ..Default::default()
            },
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return tracing::error!("Failed to map port: {e:#}"),
        };
        let protocol = mapping.protocol();
        let external_port = mapping.external_port();
        let internal_port = mapping.internal_port();
        let lifetime = mapping.lifetime();
        let mapping_type = mapping.mapping_type();

        // Print the mapped port information.
        tracing::info!("Successfully mapped protocol {protocol:?} on external port {external_port} to internal port {internal_port} with a lifetime of {lifetime:?} using {mapping_type:?}");

        // Try to safely drop the mapping.
        if let Err((e, m)) = mapping.try_drop().await {
            tracing::error!(
                "Failed to drop mapping {protocol:?} {gateway}:{}->{}: {e:?}",
                m.external_port(),
                m.internal_port()
            );
        } else {
            tracing::info!("Successfully deleted the mapping...");
        }
    }
}
