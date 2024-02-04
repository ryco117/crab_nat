/// Valid result codes from a PCP response.
/// See <https://www.rfc-editor.org/rfc/rfc6887#section-7.4>
pub enum ResultCode {
    Success,
    UnsupportedVersion,
    NotAuthorized,
    MalformedRequest,
    UnsupportedOpcode,
    UnsupportedOption,
    MalformedOption,
    NetworkFailure,
    NoResources,
    UnsupportedProtocol,
    UserExceededQuota,
    CannotProvideExternal,
    AddressMismatch,
    ExcessiveRemotePeers,
}
