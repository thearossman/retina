// Additional traffic layers built on top of the L4 base transport layer.

use super::conn_actions::TrackedActions;
use super::{LayerState, StateTransition};
use crate::subscription::Trackable;
use crate::protocols::stream::{ParseResult, ProbeRegistryResult, ConnParser, ParserRegistry, ParsingState};
use crate::protocols::Session;
use crate::L4Pdu;

/// "Layer", roughly mapped to OSI layer
/// Ordering is derived by list order
/// Each associated datatype must implement LayerInfo API (see below)
#[derive(Debug)]
pub(crate) enum Layer {
    /// L6/L7 Session
    L7(L7Session),
}
pub(crate) const NUM_LAYERS: usize = 1;

/// Trait implemented for each Layer variant
pub(crate) trait TrackableLayer {
    /// Ingest the next packet in the stream (reassembled, if TCP).
    /// Returns State transition(s) triggered.
    /// If multiple state transitions are triggered, the "Streaming" (InX)
    /// should be returned first. This will invoke methods on `T` based
    /// on the Layer and current State.
    fn process_stream<T: Trackable>(
        &mut self,
        pdu: &mut L4Pdu,
        tracked: &mut T,
        registry: &ParserRegistry,
    ) -> [StateTransition; 2];

    /// Should be checked directly after a state transition to see
    /// if process_stream needs to be called again.
    /// For example, the packet used to "discover" a protocol will
    /// also be part of its header.
    fn needs_process(&self, tx: StateTransition) -> bool;

    /// Called before applying a state transition on tracked data
    /// Will clear all active Actions that need to be "re-checked"
    /// at this state transition.
    fn reset_actions(&mut self, state: StateTransition);

    /// No actions are active and, if applicable, no sub-layers have
    /// active actions.
    fn drop(&self) -> bool;
}

impl TrackableLayer for Layer {

    fn process_stream<T: Trackable>(
        &mut self,
        pdu: &mut L4Pdu,
        tracked: &mut T,
        registry: &ParserRegistry,
    ) -> [StateTransition; 2] {
        match self {
            Layer::L7(session) => session.process_stream(pdu, tracked, registry),
        }
    }

    fn reset_actions(&mut self, tx: StateTransition) {
        match self {
            Layer::L7(session) => session.reset_actions(tx),
        }
    }

    fn needs_process(&self, tx: StateTransition) -> bool {
        match self {
            Layer::L7(session) => session.needs_process(tx),
        }
    }

    fn drop(&self) -> bool {
        match self {
            Layer::L7(session) => session.drop(),
        }
    }

}

/// Stored for each Layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerInfo {
    pub state: LayerState,
    pub actions: TrackedActions,
}

impl LayerInfo {
    pub fn new() -> Self {
        Self {
            state: LayerState::Discovery,
            actions: TrackedActions::new(),
        }
    }

    pub(crate) fn reset_actions(&mut self, tx: StateTransition) {
        self.actions.active &= self.actions.refresh_at[tx as usize].not();
    }

    pub(crate) fn drop(&self) -> bool {
        self.state == LayerState::None || self.actions.drop()
    }
}

/// L6/L7 parsing infrastructure
#[derive(Debug)]
pub struct L7Session {
    /// Layer management
    pub linfo: LayerInfo,
    /// Stateful protocol parser (once identified, or None)
    pub parser: ConnParser,
    // Further encapsulated layers could go here.
}

// TODO revisit visibility
impl L7Session {
    /// Initialize infrastructure for probing, parsing, and tracking
    /// L6/L7 (application-layer) sessions.
    pub fn new() -> Self {
        Self {
            linfo: LayerInfo::new(),
            parser: ConnParser::Unknown,
        }
    }

    /// Accessors for Sessions
    pub fn pop_session(&mut self, id: usize) -> Option<Session> {
        self.parser.remove_session(id)
    }

    /// Accessors for Sessions
    pub fn drain_sessions(&mut self) -> Vec<Session> {
        self.parser.drain_sessions()
    }
}

impl TrackableLayer for L7Session {

    fn needs_process(&self, tx: StateTransition) -> bool {
        matches!(tx, StateTransition::L7OnDisc | StateTransition::L7EndHdrs)
    }

    fn reset_actions(&mut self, tx: StateTransition) {
        self.linfo.reset_actions(tx);
    }

    fn drop(&self) -> bool {
        self.linfo.drop()
    }

    fn process_stream<T: Trackable>(
        &mut self,
        pdu: &mut L4Pdu,
        tracked: &mut T,
        registry: &ParserRegistry,
    ) -> [StateTransition; 2] {
        let mut state_tx = [StateTransition::None; 2];
        match self.linfo.state {
            LayerState::Discovery => {
                match registry.probe_all(pdu) {
                    ProbeRegistryResult::Some(conn_parser) => {
                        // Application-layer protocol known
                        self.parser = conn_parser;
                        state_tx[0] = StateTransition::L7OnDisc;
                        self.linfo.state = LayerState::Headers;
                    }
                    ProbeRegistryResult::None => {
                        // All relevant parsers have failed to match
                        state_tx[0] = StateTransition::L7OnDisc;
                        self.linfo.state = LayerState::None;
                    }
                    ProbeRegistryResult::Unsure => { /* skip */ }
                }
            }
            LayerState::Headers => {
                match self.parser.parse(pdu) {
                    let mut new_state = self.linfo.state;
                    ParseResult::Done(_) => {
                        state_tx[1] = StateTransition::L7EndHdrs;
                        new_state = LayerState::Payload;
                    },
                    ParseResult::None => {
                        state_tx[1] = StateTransition::L7EndHdrs;
                        new_state = LayerState::None;
                    },
                    _ => { /* continue */ }
                }
                if let Some(offset) = self.parser.body_offset() {
                    pdu.set_app_offset(offset);
                }
                if tracked.update(pdu, DataLevel::L7InHdrs) {
                    state_tx[0] = StateTransition::L7InHdrs;
                }
                self.linfo.state = new_state;
            }
            LayerState::Payload => {
                // TODO if no payload in this PDU (first PDU) return immediately
                if tracked.update(pdu, DataLevel::L7InPayload) {
                    state_tx[0] = StateTransition::L7InPayload;
                }
                // TODO - add API for parser to consume payload
                // if applicable and return when session is "done"
            }
            LayerState::None => {
                // Do nothing
            }
        }
        state_tx
    }
}
