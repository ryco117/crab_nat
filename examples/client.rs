use std::{net::IpAddr, num::NonZeroU16};

use crab_nat::PortMappingOptions;

/// A simple command line utility to manage NAT-PMP and PCP port mappings.
#[derive(clap::Parser)]
struct Cli {
    /// Delete the port mapping on exit. Useful only for testing/debugging.
    #[arg(short, long)]
    delete: bool,

    /// Delete all port mappings for the protocol through NAT-PMP. No mappings are created.
    #[arg(long)]
    delete_all: bool,

    /// The gateway address to use. If empty, will attempt to determine a default gateway.
    #[arg(short, long)]
    gateway: Option<String>,

    /// The local address the gateway will expect to see our address as. If empty, will attempt to determine a default network address.
    #[arg(short, long)]
    local_address: Option<String>,

    /// The internal port to map into.
    #[arg(short = 'p', long, default_value_t = NonZeroU16::new(8080).unwrap())]
    internal_port: NonZeroU16,

    /// The external port to try to map. Server is not guaranteed to use this port.
    #[arg(short = 'e', long)]
    external_port: Option<NonZeroU16>,

    /// Fetch the external IP address through NAT-PMP and exit.
    #[arg(short = 'x', long)]
    external_ip: bool,

    /// The protocol to map. Either "tcp" or "udp".
    #[arg(short, long, default_value = "udp")]
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

    let local_address = args.local_address.filter(|a| !a.is_empty()).map_or_else(
        || netdev::interface::get_local_ipaddr().expect("Could not determine a local address"),
        |address| {
            address
                .parse()
                .expect("Invalid local address, must be an IP address")
        },
    );
    tracing::info!("Using local address: {local_address}");

    // Get the gateway address from the command line or guess the default.
    let gateway = args.gateway.filter(|g| !g.is_empty()).map_or_else(
        || {
            // Attempt to get a sensible default gateway.
            let gateway = netdev::get_default_gateway().expect("Could not determine a gateway");

            // Attempt to get a gateway address matching the IP version of the local address.
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
        },
        |gateway| {
            gateway
                .parse()
                .expect("Invalid gateway, must be an IP address")
        },
    );
    tracing::info!("Using gateway address: {gateway}");

    // If the delete all flag is set, attempt to delete all mappings for the protocol and exit.
    if args.delete_all {
        crab_nat::natpmp::try_drop_mapping(gateway, protocol, None, None)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("Failed to delete mappings: {e:#}");
            });
        tracing::info!("Successfully deleted all mappings for protocol {protocol}");
        return;
    }

    // If the external IP flag is set, attempt to get the external IP and exit.
    if args.external_ip {
        let external_ip = match crab_nat::natpmp::external_address(gateway, None).await {
            Ok(ip) => ip,
            Err(e) => return tracing::error!("Failed to get external IP: {e:#}"),
        };
        return tracing::info!("External IP: {external_ip}");
    }

    // Attempt a port mapping request.
    let mapping = match crab_nat::PortMapping::new(
        gateway,
        local_address,
        protocol,
        args.internal_port,
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
    tracing::info!("Successfully mapped protocol {protocol} on external port {external_port} to internal port {internal_port} with a lifetime of {lifetime} seconds using {mapping_type}");

    if args.delete {
        // Try to safely drop the mapping.
        if let Err((e, m)) = mapping.try_drop().await {
            tracing::error!(
                "Failed to drop mapping {protocol} {gateway}:{}->{}: {e:#}",
                m.external_port(),
                m.internal_port()
            );
        } else {
            tracing::info!("Successfully deleted the mapping...");
        }
    }
}
