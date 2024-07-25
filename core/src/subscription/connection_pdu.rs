use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

/// PDUs in a TCP or UDP connection.
#[derive(Debug)]
pub struct ConnectionPdu {
    pub pdu: L4Pdu,
}

impl Subscribable for ConnectionPdu {
    type Tracked = TrackedConnectionPdu;

    fn level() -> Level {
        Level::Connection
    }

    fn parsers() -> Vec<ConnParser> {
        vec![]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        match subscription.filter_packet(&mbuf) {
            FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                if let Ok(ctxt) = L4Context::new(&mbuf, idx) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
            FilterResult::NoMatch => drop(mbuf),
        }
    }
}

/// Tracks connection frames throughout the duration of the connection lifetime.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedConnectionPdu {
    /// Buffers packets in the connection prior to a filter match.
    buf: Vec<ConnectionPdu>,
}

impl Trackable for TrackedConnectionPdu {
    type Subscribed = ConnectionPdu;

    fn new(_: FiveTuple) -> Self {
        TrackedConnectionPdu {
            buf: vec![],
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.buf
            .push(ConnectionPdu { pdu });
    }

    fn on_match(&mut self, _session: Session, subscription: &Subscription<Self::Subscribed>) {
        self.buf.drain(..).for_each(|frame| {
            subscription.invoke(frame);
        });
    }

    fn post_match(&mut self, pdu: L4Pdu, subscription: &Subscription<Self::Subscribed>) {
        subscription.invoke(ConnectionPdu { pdu} );
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        self.buf.drain(..).for_each(|frame| {
            subscription.invoke(frame);
        });
    }

}
