// Consume_PDU [invoked on first pkt and UDP [in update], + via reassembled TCP]
// Update [invoked on non-first pkt]
// Must now store actions
// Terminate handler
// Probe, parse, etc.

use super::conn_actions::TrackedActions;
use crate::lcore::CoreId;
use crate::protocols::stream::{ConnData, ParserRegistry};
use crate::subscription::{Subscription, Trackable};
use crate::FiveTuple;
use crate::L4Pdu;

use super::{conn_layers::*, conn_state::*};

/// Per-connection struct. Tracks all subscription-requested
/// datatypes (`tracked` data). Maintains the State of the connection
/// at each layer, including the `Actions` to execute when new
/// packets are received.
/// This must be public in order to be accessible by generated filter
/// and update code.
#[derive(Debug)]
pub struct ConnInfo<T>
where
    T: Trackable,
{
    /// Actions and state from the perspective of L4.
    /// Valid states are Payload or None.
    pub linfo: LayerInfo,
    /// Connection five-tuple for filtering and determining directionality
    /// of future packets.
    pub cdata: ConnData,
    /// Additional Layers that the L4 conn. should pass
    /// data to.
    pub layers: [Layer; NUM_LAYERS],
    /// Subscription data (for delivering)
    pub tracked: T,
}

impl<T> ConnInfo<T>
where
    T: Trackable,
{
    pub(super) fn new(pdu: &L4Pdu, core_id: CoreId) -> Self {
        let five_tuple = FiveTuple::from_ctxt(pdu.ctxt);
        ConnInfo {
            linfo: LayerInfo {
                state: LayerState::Payload,
                actions: TrackedActions::new(),
            },
            cdata: ConnData::new(five_tuple),
            layers: [Layer::L7(L7Session::new())],
            tracked: T::new(pdu, core_id),
        }
    }

    /// Initializes actions at all layers when first packet
    /// in L4 connection is observed.
    pub(crate) fn filter_first_packet(
        &mut self,
        pdu: &L4Pdu,
        subscription: &Subscription<T::Subscribed>,
    ) {
        subscription.filter_packet::<T>(self, pdu.mbuf_ref());
    }

    /// Update tracked data when new packet is observed.
    /// For TCP connections, this is invoked either pre-reassembly OR post-
    /// reassembly (not both). The L4Pdu will be marked with the `reassembled`
    /// flag if it has passed through the TCP reassembly module.
    pub(crate) fn new_packet(&mut self, pdu: &L4Pdu, subscription: &Subscription<T::Subscribed>) {
        if self.linfo.actions.needs_update() {
            if self.tracked.update(pdu, DataLevel::L4InPayload(pdu.ctxt.reassembled)) {
                self.exec_state_tx(StateTransition::L4InPayload(pdu.ctxt.reassembled), subscription);
            }
        }
    }

    /// Invoked by reassembly infrastructure when the TCP handshake is completed.
    pub(super) fn handshake_done(&mut self, subscription: &Subscription<T::Subscribed>) {
        self.exec_state_tx(StateTransition::L4EndHshk, subscription);
    }

    /// Invoked by transport layer to update data for encapsulated layers.
    /// This is invoked in reassembled order for TCP and received order for UDP.
    pub(crate) fn consume_stream(
        &mut self,
        pdu: &mut L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        // Update tracked data
        self.new_packet(pdu, subscription);
        // Pass to next layer(s) if applicable
        if !self.layers[0].drop() {
            let tx_ = self.layers[0].process_stream(pdu, &mut self.tracked, registry);
            for tx in tx_ {
                if tx == StateTransition::None { continue; }
                self.exec_state_tx(tx, subscription);
                if self.layers[0].needs_process(tx, pdu) {
                    self.layers[0].process_stream(pdu, &mut self.tracked, registry);
                }
            }
        }
    }

    /// Drop the connection, e.g. due to timeout
    pub(crate) fn exec_drop(&mut self) {
        self.linfo.state = LayerState::None
    }

    /// Returns true if the connection should be dropped
    pub(crate) fn drop(&self) -> bool {
        self.linfo.state == LayerState::None
    }

    /// Invoked when the connection has terminated (by timeout or TCP FIN/ACK sequence)
    /// Delivers any "end of connection" data.
    pub(crate) fn handle_terminate(&mut self, subscription: &Subscription<T::Subscribed>) {
        self.exec_state_tx(StateTransition::L4Terminated, subscription);
    }

    /// Update subscription data and current state, including actions,
    /// upon state transition.
    fn exec_state_tx(&mut self, tx: StateTransition, subscription: &Subscription<T::Subscribed>) {
        debug_assert!(tx != StateTransition::None);
        self.linfo.actions.start_state_tx(tx);
        for layer in self.layers.iter_mut() {
            layer.layer_info_mut().actions.start_state_tx(tx);
        }
        match tx {
            StateTransition::L7OnDisc => subscription.filter_protocol::<T>(self),
            StateTransition::L7EndHdrs => subscription.filter_session::<T>(self),
            StateTransition::L4Terminated => subscription.connection_terminated::<T>(self),
            StateTransition::L4EndHshk => subscription.handshake_done::<T>(self),
            StateTransition::L4InPayload(_)
            | StateTransition::L7InHdrs
            | StateTransition::L7InPayload => {
                subscription.in_update::<T>(self, tx);
            }
            StateTransition::L7EndPayload => unimplemented!(),
            StateTransition::L4FirstPacket | StateTransition::None => {}
        }

        for layer in &mut self.layers {
            layer.end_state_tx();
        }
        if self.linfo.drop() && self.layers.iter().all(|l| l.drop()) {
            self.exec_drop();
        } else {
            if self.layers.iter().any(|l| !l.drop()) {
                self.linfo.actions.set_next_layer();
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.tracked.clear();
    }

    pub(crate) fn needs_reassembly(&self) -> bool {
        self.linfo.actions.needs_reassembly() || self.linfo.actions.has_next_layer()
    }
}
