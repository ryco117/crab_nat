# 🦀 NAT

A library providing a pure Rust implementation of a client for both the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)) and the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)).

This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asynchronous and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and to succinctly handle timeouts on UDP sockets.

## Usage
If there isn't a preference on which port mapping protocol is used or what the external port should be, etc., then usage looks as follows:
```rust
// Attempt a port mapping request through PCP first and fallback to NAT-PMP.
let mapping = match crab_nat::PortMapping::new(
    gateway, /* Address of the PCP server, often a gateway or firewall */
    local_address, /* Address of our client, as seen by the gateway. Only used by PCP */
    crab_nat::InternetProtocol::Tcp, /* Protocol to map */
    std::num::NonZeroU16::new(8080).unwrap(), /* Internal port, cannot be zero */
    crab_nat::PortMappingOptions::default(), /* Optional configuration values, including suggested external port and lifetimes */
)
.await
{
    Ok(m) => m,
    Err(e) => return eprintln!("Failed to map port: {e:?}"),
};

// ...

// Try to safely drop the mapping.
if let Err((e, m)) = mapping.try_drop().await {
    eprintln!("Failed to drop mapping {}:{}->{}: {e:?}", m.gateway(), m.external_port(), m.internal_port());
} else {
    println!("Successfully deleted the mapping...");
}
```

Crab NAT does not determine the gateway address or the local client address. This is to reduce unnecessary assumptions about how this library will be used. For an easy API to determine these values reliably, I recommend using [netdev](https://crates.io/crates/netdev); see the example [client](examples/client.rs) for basic usage.

### Crate Features
* `tracing`: Enables logging of UDP packet retry attempts using the [tracing](https://github.com/tokio-rs/tracing) crate. This currently only shows UDP retry attempts at an `INFO` verbosity level.

### Missing Implementation Details
* NAT-PMP:
  * https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1 states that NAT-PMP clients should listen for external IP address changes from the gateway. This is not currently implemented, and I am unsure how useful this would be.
* PCP:
  * PCP supports more protocols than just UDP and TCP which are not yet added. I'm open to supporting more protocols if they are requested.
  * PCP defines a number of operation `Options` which are not implemented. I'm open to supporting some options if they are requested.
  * PCP describes an `Announce` operation, which I don't plan to implement.