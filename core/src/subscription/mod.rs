use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::{ConnInfo, ConnTracker, DataLevel, StateTransition};
use crate::filter::*;
use crate::lcore::CoreId;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::protocols::stream::{ParserRegistry, Session};
use crate::stats::{StatExt, TCP_BYTE, TCP_PKT, UDP_BYTE, UDP_PKT};

#[cfg(feature = "timing")]
use crate::timing::timer::Timers;

pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;
}

pub trait Trackable {
    type Subscribed: Subscribable<Tracked = Self>;

    /// Create a new struct for tracking connection data for user delivery
    fn new(first_pkt: &L4Pdu, core_id: CoreId) -> Self;

    /// Get a reference to all sessions that matched filter(s) in connection
    fn sessions(&self) -> &Vec<Session>;

    /// Store a session that matched
    fn track_session(&mut self, session: Session);

    /// Store packets for (possible) future delivery
    fn buffer_packet(&mut self, pdu: &L4Pdu, actions: &Actions, reassembled: bool);

    /// Get reference to stored packets (those buffered for delivery)
    fn packets(&self) -> &Vec<Mbuf>;

    /// Drain data from all types that require storing packets
    /// Can help free mbufs for future use
    fn drain_tracked_packets(&mut self);

    /// Check and potentially deliver to streaming callbacks
    fn stream_deliver(&mut self, actions: &mut Actions, pdu: &L4Pdu);

    /// Drain data from packets cached for future potential delivery
    /// Used after these packets have been delivered or when associated
    /// subscription fails to match
    fn drain_cached_packets(&mut self);

    /// Return the core ID that this tracked conn. is on
    fn core_id(&self) -> &CoreId;

    /// Parsers needed by all datatypes
    /// Parsers needed by filter are generated on program startup
    fn parsers() -> ParserRegistry;

    /// Clear all internal data
    fn clear(&mut self);

    /// Invoke "update" API, returning `true` if Actions may need
    /// to be refreshed (i.e., a subscription has gone out of scope).
    fn update(&mut self, pdu: &L4Pdu, state: DataLevel) -> bool;
}

#[allow(dead_code)]
pub struct Subscription<S>
where
    S: Subscribable,
{
    packet_continue: PacketContFn,
    packet_filter: PacketFilterFn<S::Tracked>,
    proto_filter: ProtoFilterFn<S::Tracked>,
    session_filter: SessionFilterFn<S::Tracked>,
    packet_deliver: PacketDeliverFn<S::Tracked>,
    conn_deliver: ConnDeliverFn<S::Tracked>,
    #[cfg(feature = "timing")]
    pub(crate) timers: Timers,
}

#[allow(dead_code)]
impl<S> Subscription<S>
where
    S: Subscribable,
{
    pub fn new(factory: FilterFactory<S::Tracked>) -> Self {
        Subscription {
            packet_continue: factory.packet_continue,
            packet_filter: factory.packet_filter,
            proto_filter: factory.proto_filter,
            session_filter: factory.session_filter,
            packet_deliver: factory.packet_deliver,
            conn_deliver: factory.conn_deliver,
            #[cfg(feature = "timing")]
            timers: Timers::new(),
        }
    }

    pub fn process_packet(
        &self,
        mbuf: Mbuf,
        conn_tracker: &mut ConnTracker<S::Tracked>,
        actions: Actions,
    ) {
        if actions.data.intersects(ActionData::PacketContinue) {
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                match ctxt.proto {
                    TCP_PROTOCOL => {
                        TCP_PKT.inc();
                        TCP_BYTE.inc_by(mbuf.data_len() as u64);
                    }
                    UDP_PROTOCOL => {
                        UDP_PKT.inc();
                        UDP_BYTE.inc_by(mbuf.data_len() as u64);
                    }
                    _ => {}
                }
                conn_tracker.process(mbuf, ctxt, self);
            }
        }
    }

    // TODO: packet continue filter should ideally be built at
    // compile-time based on what the NIC supports (what has
    // already been filtered out in HW).
    // Ideally, NIC would `mark` mbufs as `deliver` and/or `continue`.
    /// Invokes the software packet filter.
    /// Used for each packet to determine
    /// forwarding to conn. tracker. /// TMP - todo return bool
    pub fn continue_packet(&self, _mbuf: &Mbuf, _core_id: &CoreId) -> Actions {
        Actions::new()
    }

    /// Initializes connection actions by filtering on the first packet in the connection.
    pub fn filter_packet<T: Trackable>(&self, _conn: &mut ConnInfo<T>, _mbuf: &Mbuf) {}

    /// Invokes the L6/L7 protocol filter, i.e., filtering on the protocol (e.g., TLS, HTTP)
    pub fn filter_protocol<T: Trackable>(&self, _conn: &mut ConnInfo<T>) {}

    /// Invokes the Session filter, i.e., filtering on fields in a parsed session.
    pub fn filter_session<T: Trackable>(&self, _conn: &mut ConnInfo<T>) {}

    /// Invokes any L4 Connection-level subscriptions
    pub fn connection_terminated<T: Trackable>(&self, _conn: &mut ConnInfo<T>) {}

    /// Indicates that the TCP handshake has completed
    pub fn handshake_done<T: Trackable>(&self, _conn: &mut ConnInfo<T>) {}

    /// Invoked if an `update` method returned `true`, indicating that some Actions need
    /// to be refreshed. The `state` parameter helps the subscription determine which
    /// set of filter predicates to apply.
    pub fn in_update<T: Trackable>(&self, _conn: &mut ConnInfo<T>, _state: &StateTransition) {}
}

/// For `update` methods, the order of the packet received.
#[derive(Debug, Eq, PartialEq)]
pub enum L4Order {
    /// UDP connection, reassembly not applicable
    None,
    /// TCP connection, post-reassembly
    Reassembled,
    /// TCP connection, pre-assembly (order observed)
    Received,
}
