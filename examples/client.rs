#[derive(clap::Parser)]
struct Cli {
    #[arg(short, long, default_value = "")]
    gateway: String,

    #[arg(short = 'p', long, default_value_t = 8080)]
    internal_port: u16,

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

    // Attempt a NAT-PMP request to get the external IP.
    let external_ip = match crab_nat::natpmp::try_external_address(gateway).await {
        Ok(ip) => ip,
        Err(e) => return eprintln!("Failed to get external IP: {e:#}"),
    };
    println!("External IP: {external_ip:#}");

    // Attempt a port mapping request.
    let crab_nat::PortMapping {
        protocol,
        internal_port,
        external_port,
        lifetime,
        ..
    } = match crab_nat::try_port_mapping(
        gateway,
        crab_nat::MappingProtocol::Tcp,
        args.internal_port,
        args.external_port,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return eprintln!("Failed to map port: {e:#}"),
    };

    // Print the mapped port information.
    println!("Success!\nMapped protocol {protocol:?} on external port {external_port} to internal port {internal_port} with a lifetime of {lifetime:?}");
}
