# 🦀 NAT

A pure Rust library implementation of a client capable of both NAT-PMP (NAT Port Mapping Protocol, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)) and PCP (Port Control Protocol, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)).

### Missing Features
* https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1 states that clients should listen for external IP address changes from the gateway. This is not currently implemented, and I am unsure how interseting this would be to others.