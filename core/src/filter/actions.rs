//! For each connection, the Retina framework applies multiple filtering stages as
//! packets are received in order to determine (1) whether packets from that connection
//! should continue to be processed and (2) what to do with these packets.
//!
//! Each connection is associated with a set of Actions. These actions specify the
//! operations the framework will perform for the connection *now or in the future*:
//! e.g., probe for the application-layer protocol (until it is identified), deliver
//! the connection (when it has terminated), deliver all subsequent packets in the
//! connection, etc. An empty Actions struct will cause the connection to be dropped.
//!
//! Each filter stage returns a set of actions and a set of terminal actions.
//! The terminal actions are the subset of actions that are maintained through
//! the next filter stage.
use bitmask_enum::bitmask;
use std::fmt;

#[bitmask]
#[bitmask_config(vec_debug)]
pub enum ActionData {
    /// Forward new packet to connection tracker
    /// Should only be used in the PacketContinue filter
    PacketContinue,

    /// Deliver future packet data (via the PacketDelivery filter) in this connection to a callback
    /// TCP packets are delivered with the following specifications:
    /// - Packet-level filters (can match at packet stage): in the order received (pre-reassembly)
    /// - All other filters: post-reassembly
    PacketDeliver,

    /// Store packets in this connection in tracked data for
    /// potential future delivery. Used on a non-terminal match
    /// for a packet-level datatype.
    PacketCache,
    /// Store packets in this connection in tracked data for a
    /// datatype that requires tracking and delivering packets.
    PacketTrack,

    /// Probe for (identify) the application-layer protocol
    ProtoProbe,
    /// Once the application-layer protocl is identified, apply the ProtocolFilter.
    ProtoFilter,

    /// Once the application-layer session has been parsed, apply the SessionFilter
    SessionFilter,
    /// Once the application-layer session has been parsed, deliver it (by applying
    /// the SessionFilter).
    SessionDeliver,
    /// Once the application-layer session has been parsed, store it in tracked data.
    SessionTrack,

    /// The subscribable type "update" methods should be invoked (for TCP: pre-reassembly)
    UpdatePDU,

    /// The subscribable type "update" methods should be invoked post-reassembly (TCP only)
    Reassemble,

    /// Deliver connection data (via the ConnectionDelivery filter) when it terminates
    ConnDeliver,

    /// Invoke any active streaming callbacks.
    Stream,
}

/// Actions maintained per-connection
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Actions {
    /// All actions (terminal and non-terminal) that should
    /// be performed following the application of a filter.
    pub data: ActionData,
    /// All actions that should continue to be performed
    /// regardless of what the next filter returns
    /// E.g., if a terminal match for a connection-level filter
    /// occurs at the packet layer, we should continue tracking
    /// the connection regardless of later filter results.
    pub terminal_actions: ActionData,
}

impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}

impl Actions {
    // Create an empty Actions bitmask
    pub fn new() -> Self {
        Self {
            data: ActionData::none(),
            terminal_actions: ActionData::none(),
        }
    }

    // Store the result of a new filter
    // Used at runtime after application of next filter
    #[inline]
    pub fn update(&mut self, actions: &Actions) {
        self.data = self.terminal_actions | actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    // Combine terminal and non-terminal actions
    // Used for building a filter tree at compile time and when
    // applying a filter at runtime if additional conditions are met.
    #[inline]
    pub fn push(&mut self, actions: &Actions) {
        self.data |= actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    // Returns true if no actions are set (i.e., the connection can
    // be dropped by the framework).
    #[inline]
    pub fn drop(&self) -> bool {
        self.data.is_none() && self.terminal_actions.is_none()
    }

    // Update `self` to contain only actions not in `actions`
    #[inline]
    pub(crate) fn clear_intersection(&mut self, actions: &Actions) {
        self.data &= actions.data.not();
        self.terminal_actions &= actions.data.not();
    }
}

use proc_macro2::{Ident, Span};
use quote::{quote, ToTokens};
use std::str::FromStr;

impl FromStr for ActionData {
    type Err = core::fmt::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PacketContinue" => Ok(ActionData::PacketContinue),
            "PacketDeliver" => Ok(ActionData::PacketDeliver),
            "ProtoProbe" => Ok(ActionData::ProtoProbe),
            "ProtoFilter" => Ok(ActionData::ProtoFilter),
            "SessionFilter" => Ok(ActionData::SessionFilter),
            "SessionDeliver" => Ok(ActionData::SessionDeliver),
            "SessionTrack" => Ok(ActionData::SessionTrack),
            "UpdatePDU" => Ok(ActionData::UpdatePDU),
            "Reassemble" => Ok(ActionData::Reassemble),
            "PacketTrack" => Ok(ActionData::PacketTrack),
            "PacketCache" => Ok(ActionData::PacketCache),
            "ConnDeliver" => Ok(ActionData::ConnDeliver),
            _ => Result::Err(core::fmt::Error),
        }
    }
}

impl fmt::Display for ActionData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            ActionData::PacketContinue => "PacketContinue",
            ActionData::PacketDeliver => "PacketDeliver",
            ActionData::ProtoProbe => "ProtoProbe",
            ActionData::ProtoFilter => "ProtoFilter",
            ActionData::SessionFilter => "SessionFilter",
            ActionData::SessionDeliver => "SessionDeliver",
            ActionData::SessionTrack => "SessionTrack",
            ActionData::UpdatePDU => "UpdatePDU",
            ActionData::Reassemble => "Reassemble",
            ActionData::PacketTrack => "PacketTrack",
            ActionData::PacketCache => "PacketCache",
            ActionData::ConnDeliver => "ConnDeliver",
            _ => panic!("Unknown ActionData"),
        };
        write!(f, "{}", s)
    }
}

impl ToTokens for ActionData {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name_ident = Ident::new(&self.to_string(), Span::call_site());
        let enum_ident = Ident::new("ActionData", Span::call_site());
        tokens.extend(quote! { #enum_ident::#name_ident });
    }
}

impl FromStr for Actions {
    type Err = core::fmt::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Actions::new();
        let split = s.split("|");
        for str in split {
            let terminal = str.contains("(T)");
            let action_str = str.replace("(T)", "");
            if let Ok(a) = ActionData::from_str(action_str.trim()) {
                result.data |= a;
                if terminal {
                    result.terminal_actions |= a;
                }
            } else {
                return Result::Err(core::fmt::Error);
            }
        }
        Ok(result)
    }
}

impl ToTokens for Actions {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let bits = syn::LitInt::new(&self.data.bits.to_string(), Span::call_site());
        let terminal_bits =
            syn::LitInt::new(&self.terminal_actions.bits.to_string(), Span::call_site());
        tokens.extend(quote! {
        Actions { data: ActionData::from(#bits),
                  terminal_actions: ActionData::from(#terminal_bits) } });
    }
}
