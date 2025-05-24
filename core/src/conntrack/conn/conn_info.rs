// Consume_PDU [invoked on first pkt and UDP [in update], + via reassembled TCP]
// Update [invoked on non-first pkt]
// Must now store actions
// Terminate handler
// Probe, parse, etc.

use crate::L4Pdu;
use super::conn_actions::TrackedActions;
use crate::lcore::CoreId;
use crate::protocols::stream::{ConnData, ParserRegistry};
use crate::subscription::{Subscription, Trackable};
use crate::FiveTuple;
use crate::protocols::packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL};

use super::{conn_state::*, conn_layers::*};

/// Per-connection struct. Tracks all subscription-requested
/// datatypes (`tracked` data). Maintains the State of the connection
/// at each layer, including the `Actions` to execute when new
/// packets are received.
#[derive(Debug)]
pub struct ConnInfo<T>
where
    T: Trackable,
{
    /// Actions and state from the perspective of L4.
    /// Valid states are Payload or None.
    pub(crate) linfo: LayerInfo,
    /// Connection five-tuple for filtering and determining directionality
    /// of future packets.
    pub(crate) cdata: ConnData,
    /// Additional Layers that the L4 conn. should pass
    /// data to.
    pub(crate) layers: [Layer; NUM_LAYERS],
    /// Subscription data (for delivering)
    pub(crate) tracked: T,
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
        subscription.filter_packet(self, pdu.mbuf_ref());
    }

    /// New packet associated with the connection observed.
    /// Updates tracked data.
    /// Note that InHandshake is processed post-reassembly.
    pub(crate) fn new_packet(&mut self, pdu: &L4Pdu,
                             subscription: &Subscription<T::Subscribed>) {
        if self.actions.update() {
            if self.tracked.update(pdu, DataLevel::L4InPayload) {
                self.exec_state_tx(StateTransition::L4InPayload, subscription);
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
        registry: &ParserRegistry)
    {
        self.new_packet(pdu, subscription);
        let tx_ = self.layers[0].process_stream(pdu, &mut self.tracked, registry);
        for tx in tx_ {
            self.exec_state_tx(tx, subscription);
            if self.layers[0].needs_process(tx) {
                self.layers[0].process_stream(pdu, &mut self.tracked, registry);
            }
        }
    }

    /// Drop the connection, e.g. due to timeout
    /// TODO make sure this is invoked if all actions are none after state tx
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
    fn exec_state_tx(&mut self, tx: StateTransition,
                     subscription: &Subscription<T::Subscribed>) {
        self.linfo.reset_actions(tx);
        for layer in self.layers.iter_mut() {
            layer.reset_actions(tx);
        }
        match tx {
            StateTransition::L7OnDisc => subscription.filter_protocol(self),
            StateTransition::L7EndHdrs => subscription.filter_session(self, tx),
            StateTransition::L4Terminated => subscription.connection_terminated(self),
            StateTransition::L4EndHshk => subscription.handshake_done(self),
            StateTransition::L4InPayload | StateTransition::L7InHdrs | StateTransition::L7InPayload => {
                subscription.in_update(self, tx);
            }
            StateTransition::L7EndPayload => unimplemented!(),
            StateTransition::L4FirstPacket | StateTransition::None => { }
        }

        if self.linfo.drop() &&
           self.layers.iter().all(|l| l.drop()) {
            self.exec_drop();
        }
    }

    pub(crate) fn clear(&mut self) {
        // TODO clear other layers?
        self.tracked.clear();
    }

    pub(crate) fn needs_parse(&self) -> bool {
        self.linfo.actions.parse()
    }

    pub(crate) fn needs_reassembly(&self) -> bool {
        self.linfo.state == LayerState::Headers || self.linfo.actions.reassemble()
    }
}