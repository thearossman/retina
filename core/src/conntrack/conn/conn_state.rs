use std::cmp::Ordering;
use strum_macros::EnumIter;
use strum::IntoEnumIterator;

use crate::{conntrack::Layer, protocols::{stream::SessionProto, Session}};

/// State that each Layer maintains, based on what it has
/// seen so far in the connection.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Ord, PartialOrd, Hash, EnumIter)]
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

impl std::fmt::Display for DataLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L4InPayload(_) => write!(f, "L4InPayload"), // hide encap value
            _ => write!(f, "{:?}", self),
        }
    }
}

// https://doc.rust-lang.org/reference/items/enumerations.html#casting
impl DataLevel {
    pub fn as_usize(&self) -> usize {
        self.raw() as usize
    }

    pub fn from_usize(i: usize) -> Self {
        for level in DataLevel::iter() {
            if level.as_usize() == i {
                return level;
            }
        }
        DataLevel::None
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

/// State Transitions with associated data, used as wrappers for users to subscribe to
/// TODO which mod should these live in...
#[derive(Debug)]
pub enum StateTxData {
    L4EndHshk,
    L7OnDisc(SessionProto),
    L7EndHdrs(Session),
    L4Terminated,
}

impl StateTxData {
    pub fn from_tx(state: &StateTransition, layer: &mut Layer) -> Self {
        match layer {
            Layer::L7(layer) => {
                return match state {
                    DataLevel::L4EndHshk => Self::L4EndHshk,
                    DataLevel::L7OnDisc => Self::L7OnDisc(layer.get_protocol()),
                    DataLevel::L7EndHdrs => Self::L7EndHdrs(layer.pop_session()
                                                                 .expect("L7EndHdrs without session")),
                    DataLevel::L4Terminated => Self::L4Terminated,
                    _ => panic!("Called from_tx on streaming state {:?}", state),
                };
            }
        }
    }

    // Should be the same as the corresponding StateTransition
    #[allow(dead_code)]
    pub(crate) fn as_usize(&self) -> usize {
        match self {
            StateTxData::L4EndHshk => StateTransition::L4EndHshk.as_usize(),
            StateTxData::L7OnDisc(_) => StateTransition::L7OnDisc.as_usize(),
            StateTxData::L7EndHdrs(_) => StateTransition::L7EndHdrs.as_usize(),
            StateTxData::L4Terminated => StateTransition::L4Terminated.as_usize(),
        }
    }
}


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
