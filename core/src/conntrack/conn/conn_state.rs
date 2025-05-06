/// State that each Layer maintains, based on what it has
/// seen so far in the connection.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum LayerState {
    /// Determining protocol
    Discovery,
    /// Headers (TCP hshk, TLS hshk, HTTP hdrs, etc.)
    /// Contains number of packets seen in headers.
    Headers,
    /// Headers done; new packets expected to be in layer payload
    Payload,
    /// This Layer and all child layers* should no longer
    /// receive packets. This will be set based on the
    /// result of a filter.
    None,
}

/// The possible Levels that a datatype or filter can be associated with.
/// Streaming Levels must also identify the streaming frequency and unit
/// (packets, bytes, or seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLevel {
    /// On first packet in connection
    L4FirstPacket = 0,
    /// Streaming in TCP handshake
    L4InTcpHshk,
    /// At TCP handshake end
    L4EndHshk,
    /// Streaming in L4 Payload
    /// After TCP handshake or anywhere in UDP conn.
    L4InPayload,
    /// Streaming in L4 reass. payload
    L4InStream,
    /// L4 connection terminated by FIN/ACK sequence or timeout
    L4Terminated,

    /// On L7 protocol identification
    L7OnDisc,
    /// Streaming in L7 headers
    L7InHdrs,
    /// On L6/L7 headers parsed
    L7EndHdrs,
    /// Streaming in L7 payload
    L7InPayload,
    /// L7 payload (HTTP body, TLS ciphertext, etc) done
    L7EndPayload,
    /// This is used as a no-op state transition and to give the
    /// enum a defined length. It is not a valid Level for a datatype
    /// or filter. This must be last in the enum variant list.
    None,
}

/// The State Transitions that a connection can encounter.
/// For `InX` Levels, the state transition is triggered if
/// a streaming callback or filter changed match state (i.e.,
/// was and is no longer active).
pub type StateTransition = DataLevel;
/// Number of variants; used to size the `refresh_at` array
pub(crate) const NUM_STATE_TRANSITIONS: usize = StateTransition::None as usize - 1;