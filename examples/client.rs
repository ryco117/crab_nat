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
    external_port: Option<u16>,
}

#[tokio::main]
async fn main() {
    use clap::Parser as _;
    let args = Cli::parse();

    // Get the gateway address from the command line or guess the default.
    let gateway = if args.gateway.is_empty() {
        default_net::get_default_gateway()
            .expect("Could not determine a gateway")
            .ip_addr
    } else {
        args.gateway.parse().expect("Invalid gateway format")
    };
    println!("Using gateway address: {gateway:#}");

    let local_address = if args.local_address.is_empty() {
        default_net::interface::get_local_ipaddr().expect("Could not determine a local address")
    } else {
        args.local_address
            .parse()
            .expect("Invalid local address format")
    };
    println!("Using local address: {local_address:#}");

    // Attempt a NAT-PMP request to get the external IP.
    let external_ip = match crab_nat::natpmp::try_external_address(gateway).await {
        Ok(ip) => ip,
        Err(e) => return eprintln!("Failed to get external IP: {e:#}"),
    };
    println!("External IP: {external_ip:#}");

    if args.delete {
        // Attempt a port unmapping request.
        if let Err(e) = crab_nat::natpmp::try_drop_mapping(
            gateway,
            crab_nat::InternetProtocol::Tcp,
            args.internal_port,
        )
        .await
        {
            return eprintln!("Failed to unmap port: {e:#}");
        }

        // Print the mapped port information.
        println!("Success! Deleted previous port mapping");
    } else {
        // Attempt a port mapping request.
        let crab_nat::PortMapping {
            protocol,
            internal_port,
            external_port,
            lifetime,
            version,
            ..
        } = match crab_nat::try_port_mapping(
            gateway,
            local_address,
            crab_nat::InternetProtocol::Tcp,
            args.internal_port,
            args.external_port,
            None,
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return eprintln!("Failed to map port: {e:?}"),
        };

        // Print the mapped port information.
        println!("Success!\nMapped protocol {protocol:?} on external port {external_port} to internal port {internal_port} with a lifetime of {lifetime:?} using version {version:?}");
    }
}
