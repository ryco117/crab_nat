# 🦀 NAT

A library providing a pure Rust implementation of a client for both the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)) and the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)).

This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asyncronous, and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and succinctly handle timeouts on UDP sockets.

## Usage
If there isn't a preference on which protocol is used or what the external port should be, usage looks as follows:
```rust
// Attempt a port mapping request through PCP first and fallback to NAT-PMP.
let mapping = match crab_nat::PortMapping::new(
    gateway /* Address of the PCP server, often a gateway or firewall */,
    local_address /* Address of our client, as seen by the gateway. Only used by PCP */,
    crab_nat::InternetProtocol::Tcp /* Protocol to map */,
    std::num::NonZeroU16::new(8080).unwrap() /* Internal port, cannot be zero */,
    None /* External port, no preference */,
    None /* Lifetime, use default of 2 hours */,
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

Crab NAT does not determine the gateway address or the local client address itself. I recommend using [default-net](https://crates.io/crates/default-net), see the example [client](examples/client.rs) for basic usage.

### Missing Features
* PCP describes a `Peer` operation which is not yet implemented.
* PCP describes an `Announce` operation, which I don't plan to implement.
* PCP supports more protocols than just UDP and TCP which are not yet added. I'm open to supporting more protocols if they are requested.
* PCP defines a number of "Options" which are not implemented. There is currently no plan to implement them.
* https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1 states that NAT-PMP clients should listen for external IP address changes from the gateway. This is not currently implemented, and I am unsure how useful this would be.