# 🦀 NAT

A pure Rust library implementation of a client for both the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)) and the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)).

This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asyncronous, and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and succinctly handle timeouts on UDP sockets.

### Missing Features
* PCP is not yet implemented. This is a work in progress, but it is significantly more complex than its predecessor.
* PCP supports a `Peer` operation which is not yet implemented.
* PCP defines a number of protocol options which are not implemented. There is currently no plan to implement them.
* https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1 states that clients should listen for external IP address changes from the gateway. This is not currently implemented, and I am unsure how interseting this would be to others.