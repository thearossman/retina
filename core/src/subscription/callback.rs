use super::Trackable;
use crate::L4Pdu;

/// This streaming callback trait should be used when a user can
/// accept read-only access to tracked data. If no internal state is
/// needed, the user can implement this trait on an empty struct.
/// If the user needs mutable tracked data, they should store it internally,
/// request updates on each packet, and maintain their own timer for any
/// separate processing.
pub trait StreamingCallback<T>
where
    T: Trackable,
{
    /// Initializes internal data, if applicable.
    /// Called on first packet in connection.
    fn new(first_pkt: &L4Pdu) -> Self;
    /// Invoked at specified intervals with tracked data
    /// (if a filter pattern matched). Phases of interest must
    /// be specified as attributes, e.g.: #[invoke(L4Payload)]
    /// Interval must be specified as attribute, e.g. #[streaming(packets=1)]
    /// The last PDU seen will also be delivered.
    /// If PDUs are requested, packets will be buffered until ready to be delivered.
    fn invoke(&mut self, data: &T, last_pkt: &L4Pdu) -> bool;
}
