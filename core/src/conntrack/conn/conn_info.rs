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
    /// "Headers" refers to the TCP handshake.
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
        let l4_state = match pdu.ctxt.proto {
            TCP_PROTOCOL => LayerState::Headers,
            UDP_PROTOCOL => LayerState::Payload,
            _ => panic!("Unsupported protocol"),
        };
        ConnInfo {
            linfo: LayerInfo {
                state: l4_state,
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
        let frame_order = match pdu.ctxt.proto {
            TCP_PROTOCOL => L4Order::Received,
            _ => L4Order::None,
        };
        if self.linfo.state == LayerState::Payload &&
           self.linfo.actions.update() &&
           self.tracked.update_l4_payload(pdu, frame_order)
        {
            self.exec_state_tx(StateTransition::L4InPayload, subscription);
        }

        if pdu.ctxt.proto == TCP_PROTOCOL {
            let tx_ = self.layers[0].new_packet(pdu, &mut self.tracked, registry);
            for tx in tx_ {
                self.exec_state_tx(tx, subscription);
            }
        }
    }

    /// Only invoked for TCP connections. Post-reassembly.
    /// New transport-layer packet has been reassembled.
    /// Updates tracked data.
    pub(crate) fn new_reassembled_packet(&mut self, pdu: &L4Pdu,
                                         subscription: &Subscription<T::Subscribed>) {
        match self.linfo.state {
            LayerState::Payload => {
                if self.linfo.actions.update_reassembled() &&
                   self.tracked.update_l4_reassembled(pdu) {
                    self.exec_state_tx(StateTransition::L4InStream, subscription);
                }
            }
            LayerState::Headers => {
                if self.linfo.actions.update_any() &&
                   self.tracked.update_in_handshake(pdu) {
                    self.exec_state_tx(StateTransition::L4InTcpHshk, subscription);
                }
            },
            LayerState::Discovery | LayerState::None => {},
        }
    }

    /// Invoked by reassembly infrastructure when the TCP handshake is completed.
    /// TODO INVOKE THIS
    pub(super) fn handshake_done(&mut self, subscription: &Subscription<T::Subscribed>) {
        self.linfo.state = LayerState::Payload;
        self.exec_state_tx(StateTransition::L4EndHshk, subscription);
    }

    /// Invoked by transport layer to update data for encapsulated layers.
    /// This is invoked in reassembled order for TCP and received order for UDP.
    pub(crate) fn consume_stream(
        &mut self,
        pdu: &L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry)
    {
        if pdu.ctxt.proto == TCP_PROTOCOL {
            self.new_reassembled_packet(pdu, subscription);
        }

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
            StateTransition::L4InTcpHshk => {
                subscription.in_handshake(self);
            }
            StateTransition::L4EndHshk => {
                subscription.handshake_done(self);
            }
            StateTransition::L4InPayload => {
                subscription.in_l4_payload(self);
            }
            StateTransition::L4InStream => {
                subscription.in_tcp_stream(self);
            }
            StateTransition::L4Terminated => {
                subscription.connection_terminated(self);
            }
            StateTransition::L7OnDisc => {
                subscription.l7_identified(self);
            }
            StateTransition::L7InHdrs => {
                subscription.in_l7_hdrs(self);
            }
            StateTransition::L7EndHdrs => {
                subscription.l7_hdrs_parsed(self);
            }
            StateTransition::L7InPayload => {
                subscription.l7_in_payload(self);
            }
            StateTransition::L7EndPayload => {
                subscription.l7_payload_done(self);
            }
            _ => { }
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