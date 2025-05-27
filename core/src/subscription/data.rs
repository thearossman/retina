use crate::L4Pdu;
use crate::conntrack::StateTransition;
use crate::protocols::Session;
use crate::memory::mbuf::Mbuf;

/// Interface for datatypes that must be "tracked" throughout
/// all or part of a connection.
///
/// The datatype can optionally be tagged as #[expensive], which
/// indicates that the runtime should track which subscriptions require
/// it and drop the Tracked data if all of those subscriptions go out
/// of scope. This may limit how much the compiler can optimize the
/// filter predicates, but it is generally valuable if the datatype is memory-
/// or computationally-intensive (e.g., a list of packets).
pub trait Tracked {
    /// Initialize internal data. Invoked on first PDU in connection.
    /// Note that this first PDU will also be received in `update`.
    fn new(first_pkt: &L4Pdu);
    /// Invoked for each newly received PDU.
    /// Start/end phases of interest must be specified as attributes, e.g.
    /// #[invoke(L4InPayload)], #[invoke(L4FirstPacket,L4EndHshk)]
    fn update(&mut self, pdu: &L4Pdu);
    /// Invoked for phase transitions of interest, which must be specified
    /// as attributes.
    fn phase_tx(&mut self, tx: StateTransition);
    /// Utility method to clear internal data.
    /// Recommended to implement for memory-intensive datatypes.
    fn clear(&mut self);
}

/// Dummy struct to be used when a streaming filter does not require
/// any tracked data (i.e., just wants raw packets).
pub struct TrackedEmpty;
impl Tracked for TrackedEmpty {
    fn new(_first_pkt: &L4Pdu) {}
    fn update(&mut self, _pdu: &L4Pdu) {}
    fn phase_tx(&mut self, _tx: StateTransition) {}
    fn clear(&mut self) {}
}

/// Convenience method to convert a `Session` into a datatype that
/// can be subscribed to. Datatypes implementing this trait are
/// automatically Level=Session.
pub trait FromSession {
    fn new(session: &Session) -> Self;
}

/// Convenience method to convert an `Mbuf` into a datatype that
/// can be subscribed to. Datatypes implementing this trait
/// are automatically Level=Packet.
pub trait FromMbuf {
    fn new(mbuf: &Mbuf) -> Self;
}

/// If a datatype is specified as "expensive", it is wrapped in this
/// so that we can track when it's still needed by active subscriptions.
#[doc(hidden)]
pub struct TrackedDataWrapper<T>
where T: Tracked
{
    /// The wrapped tracked data.
    pub data: T,
    /// Has terminally matched some subscription; continue
    /// tracking until the datatype has reached its ending point.
    pub term: bool,
    /// Count of subscriptions that have matched non-terminally.
    pub nonterm: Option<u32>,
}