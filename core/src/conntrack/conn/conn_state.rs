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
#[repr(u8)]
pub enum DataLevel {
    /// On first packet in connection
    L4FirstPacket = 0,
    /// Complete TCP handshake has been observed.
    /// Note that this should not be used to indicate the beginning
    /// of payload, as payload may overlap with the handshake.
    L4EndHshk,
    /// Streaming anywhere in L4 connection, including TCP handshake.
    /// Must specify in associated data whether the packets must be
    /// reassembled (true) or not (false).
    L4InPayload(bool),
    /// L4 connection terminated by FIN/ACK sequence or timeout
    L4Terminated,

    /// On L7 protocol identification
    L7OnDisc,
    /// Streaming in L7 headers
    L7InHdrs,
    /// On L6/L7 headers parsed
    L7EndHdrs,
    /// Streaming in L7 payload (after headers)
    L7InPayload,
    /// L7 payload end. TODO NOT YET SUPPORTED by parsers.
    L7EndPayload,

    /// `None` is used as a no-op state transition and to give the
    /// enum a defined length. It is not a valid Level for a datatype
    /// or filter. This must be last in the enum variant list.
    None,
}

// https://doc.rust-lang.org/reference/items/enumerations.html#casting
impl DataLevel {
    pub fn as_usize(&self) -> usize {
        self.raw() as usize
    }

    pub fn raw(&self) -> u8 {
        unsafe { *(self as *const Self as *const u8) }
    }
}

/// The State Transitions that a connection can encounter.
/// For `InX` Levels, the state transition is triggered if
/// a streaming callback or filter changed match state (i.e.,
/// was and is no longer active).
pub type StateTransition = DataLevel;
/// Number of variants; used to size the `refresh_at` array
pub(crate) const NUM_STATE_TRANSITIONS: usize = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_level_raw() {
        assert_eq!(DataLevel::None.as_usize(), NUM_STATE_TRANSITIONS);
        assert_eq!(DataLevel::L4InPayload(true).as_usize(),
                   DataLevel::L4InPayload(false).as_usize());
    }
}
