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

    let gateway = if args.gateway.is_empty() {
        default_net::get_default_gateway()
            .expect("Could not determine a gateway")
            .ip_addr
    } else {
        args.gateway.parse().expect("Invalid gateway format")
    };
    println!("Using gateway address: {gateway:#}");

    let external_ip = crab_nat::natpmp::try_external_address(gateway)
        .await
        .expect("Failed to get external IP");
    println!("External IP: {external_ip:#}");

    let crab_nat::PortMapping { protocol, internal_port, external_port, lifetime, .. } = crab_nat::try_port_mapping(
        gateway,
        crab_nat::MappingProtocol::Tcp,
        args.internal_port,
        args.external_port
    ).await.expect("Failed to map port");

    // Print the mapped port information.
    println!("Success!\nMapped protocol {protocol:?} on external port {external_port} to internal port {internal_port} with a lifetime of {lifetime:?}");
}
