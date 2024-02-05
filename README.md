# 🦀 NAT

A library providing a pure Rust implementation of a client for both the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)) and the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)).

This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asyncronous, and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and succinctly handle timeouts on UDP sockets.

## Usage
```rust
// Attempt a port mapping request through PCP first and fallback to NAT-PMP.
let mapping = match crab_nat::try_port_mapping(
    gateway /* address of the PCP server, often a gateway or firewall */,
    local_address /* address of our client, as seen by the gateway. Only used by PCP */,
    crab_nat::InternetProtocol::Tcp,
    8080 /* internal port */,
    None /* external port, no preference */,
    None /* lifetime, use default of 2 hours */,
)
.await
{
    Ok(m) => m,
    Err(e) => return eprintln!("Failed to map port: {e:?}"),
};
```

### Missing Features
* PCP describes a `Peer` operation which is not yet implemented.
* PCP describes an `Announce` operation, which I don't plan to implement.
* PCP defines a number of protocol options which are not implemented. There is currently no plan to implement them.
* https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1 states that NAT-PMP clients should listen for external IP address changes from the gateway. This is not currently implemented, and I am unsure how useful this would be.