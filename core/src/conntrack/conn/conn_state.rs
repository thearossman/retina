use std::cmp::Ordering;
use strum_macros::EnumIter;

/// State that each Layer maintains, based on what it has
/// seen so far in the connection.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Ord, PartialOrd, Hash)]
pub enum LayerState {
    /// Determining protocol
    /// For L4, this indicates pre-handshake
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
/// NOTE: for the same layer, enums must be listed in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, EnumIter)]
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

    /// L4 connection terminated by FIN/ACK sequence or timeout
    L4Terminated,

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

    pub fn name(&self) -> &str {
        match self {
            DataLevel::L4FirstPacket => "L4FirstPacket",
            DataLevel::L4EndHshk => "L4EndHshk",
            DataLevel::L4InPayload(_) => "L4InPayload",
            DataLevel::L4Terminated => "L4Terminated",
            DataLevel::L7OnDisc => "L7OnDisc",
            DataLevel::L7InHdrs => "L7InHdrs",
            DataLevel::L7EndHdrs => "L7EndHdrs",
            DataLevel::L7InPayload => "L7InPayload",
            DataLevel::L7EndPayload => "L7EndPayload",
            DataLevel::None => "None",
        }
    }

    pub fn in_transport(&self) -> bool {
        self.name().contains("L4")
    }

    pub fn is_streaming(&self) -> bool {
        self.name().contains("In")
    }

    // Returns the layers `l` for which `l > self`
    // and `l` _could_ directly follow `self`.
    // For example, "L7OnDisc" can directly precede "L7InHdrs", but it cannot
    // directly precede "L7InPayload" because "L7EndHdrs" must come first.
    pub(crate) fn next_layers(&self) -> Vec<Self> {
        let mut ret = vec![];
        match self {
            StateTransition::L4FirstPacket => {
                ret.push(StateTransition::L4EndHshk);
                ret.push(StateTransition::L7OnDisc);
                ret.push(StateTransition::L4InPayload(true));
                ret.push(StateTransition::L4InPayload(false));
            }
            StateTransition::L4EndHshk
            | StateTransition::L4InPayload(_)
            | StateTransition::L7EndPayload
            | StateTransition::L7InPayload => {
                ret.push(StateTransition::L4Terminated);
            }
            StateTransition::L7OnDisc => {
                ret.push(StateTransition::L7EndHdrs);
                ret.push(StateTransition::L7InHdrs);
            }
            StateTransition::L7InHdrs => {
                ret.push(StateTransition::L7EndHdrs);
            }
            StateTransition::L7EndHdrs => {
                ret.push(StateTransition::L7InPayload);
            }
            StateTransition::L4Terminated | StateTransition::None => {}
        }
        ret
    }

    pub fn layer_idx(&self) -> Option<usize> {
        if self.name().contains("L7") {
            return Some(0);
        }
        None
    }

    /// Returns Greater if self > Other, Less if self < Other, Equal if self == Other,
    /// and Unknown if the two cannot be compared (different layers).
    pub fn compare(&self, other: &DataLevel) -> StateTxOrd {
        // Invalid layer for subscriptions
        assert!(!matches!(self, DataLevel::None) && !matches!(self, DataLevel::None));

        // End of connection is always greatest
        if matches!(self, DataLevel::L4Terminated) || matches!(other, DataLevel::L4Terminated) {
            return StateTxOrd::from_ord(self.cmp(other));
        }
        // Start of connection is always lowest
        if matches!(self, DataLevel::L4FirstPacket) || matches!(other, DataLevel::L4FirstPacket) {
            return StateTxOrd::from_ord(self.cmp(other));
        }

        // Different layers
        if self.name().contains("L4") && !other.name().contains("L4")
            || self.name().contains("L7") && !other.name().contains("L7")
        {
            return StateTxOrd::Unknown;
        }

        // Exceptions to the ordering rule
        if matches!(self, DataLevel::L4EndHshk) {
            return StateTxOrd::Unknown;
        }

        // Enum must be in listed order above.
        StateTxOrd::from_ord(self.cmp(other))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum StateTxOrd {
    Unknown,
    Greater,
    Less,
    Equal,
}

impl StateTxOrd {
    pub(crate) fn from_ord(ordering: Ordering) -> StateTxOrd {
        match ordering {
            Ordering::Greater => StateTxOrd::Greater,
            Ordering::Less => StateTxOrd::Less,
            Ordering::Equal => StateTxOrd::Equal,
        }
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
        assert_eq!(
            DataLevel::L4InPayload(true).as_usize(),
            DataLevel::L4InPayload(false).as_usize()
        );
    }
}
