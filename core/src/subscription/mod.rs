//! Subscribable data types.
//!
//! A subscription is a request for a callback on a subset of network traffic specified by a filter.
//! Callback functions are implemented as a closure that takes a subscribable data type as the
//! parameter and immutably borrows values from the environment. Built-in subscribable types can
//! be customized within the framework to provide additional data to the callback if needed.

pub mod connection;
pub mod connection_frame;
pub mod dns_transaction;
pub mod frame;
pub mod http_transaction;
pub mod quic_stream;
pub mod tls_handshake;
pub mod zc_frame;

use std::any::Any;

// Re-export subscribable types for more convenient usage.
pub use self::connection::Connection;
pub use self::connection_frame::ConnectionFrame;
pub use self::dns_transaction::DnsTransaction;
pub use self::frame::Frame;
pub use self::http_transaction::HttpTransaction;
pub use self::quic_stream::QuicStream;
pub use self::tls_handshake::TlsHandshake;
pub use self::zc_frame::ZcFrame;

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::{ConnFilterFn, PacketFilterFn, SessionFilterFn};
use crate::filter::{FilterFactory, FilterResult};
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnData, ConnParser, Session};

#[cfg(feature = "timing")]
use crate::timing::timer::Timers;

/// The abstraction level of the subscribable type.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Suitable for analyzing individual packets or frames where connection-level semantics are
    /// unnecessary.
    Packet,
    /// Suitable for analyzing entire connections, whether as a single record or a stream.
    Connection,
    /// Suitable for analyzing session-level data, of which there may be multiple instances per
    /// connection.
    Session,
}

pub struct SubscribableWrapper {
    subscriptions: Vec<SubscribedTypeEnum>,
    callbacks: Vec<Box<dyn Fn(dyn Any)>>,
}

impl SubscribableWrapper {
    pub fn new(
        subscriptions: Vec<SubscribedTypeEnum>,
        callbacks: Vec<Box<dyn Fn(dyn Any)>>
    ) -> Self {
        SubscribableWrapper {
            subscriptions,
            callbacks,
        }
    }

    fn level(&self) -> Level {
        let levels = self.subscriptions
            .iter()
            .map(|s| s.level())
            .collect::<Vec<>>();
        if levels.iter().any(|&l| l == Level::Connection) {
            return Level::Connection;
        }
        if levels.iter().any(|&l| l == Level::Session) {
            return Level::Session;
        }
        Level::Packet
    }

    fn parsers() -> Vec<ConnParser> {
        let mut parsers = Vec::new();
        for subscription in &self.subscriptions {
            for parser in subscription.parsers() {
                if !parsers.contains(&parser) {
                    parsers.push(parser);
                }
            }
        }
        parsers
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription,
        callbacks: &SubscribableWrapper,
        conn_tracker: &mut ConnTracker,
    ) where
        Self: Sized
    {
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

// Gross workaround (can't do `dyn` with associated types),
// but okay for naive solution
pub enum SubscribedTypeEnum {
    Connection,
    ConnectionFrame,
    DnsTransaction,
    Frame,
    HttpTransaction,
    QuicStream,
    TlsHandshake,
    ZcFrame,
}

impl SubscribedTypeEnum {
    fn level(&self) -> Level {
        match self {
            SubscribedTypeEnum::Connection => Connection::level(),
            SubscribedTypeEnum::ConnectionFrame => ConnectionFrame::level(),
            SubscribedTypeEnum::DnsTransaction => DnsTransaction::level(),
            SubscribedTypeEnum::Frame => Frame::level(),
            SubscribedTypeEnum::HttpTransaction => HttpTransaction::level(),
            SubscribedTypeEnum::QuicStream => QuicStream::level(),
            SubscribedTypeEnum::TlsHandshake => TlsHandshake::level(),
            SubscribedTypeEnum::ZcFrame => ZcFrame::level(),
        }
    }

    fn parsers(&self) -> Vec<ConnParser> {
        match self {
            SubscribedTypeEnum::Connection => Connection::parsers(),
            SubscribedTypeEnum::ConnectionFrame => ConnectionFrame::parsers(),
            SubscribedTypeEnum::DnsTransaction => DnsTransaction::parsers(),
            SubscribedTypeEnum::Frame => Frame::parsers(),
            SubscribedTypeEnum::HttpTransaction => HttpTransaction::parsers(),
            SubscribedTypeEnum::QuicStream => QuicStream::parsers(),
            SubscribedTypeEnum::TlsHandshake => TlsHandshake::parsers(),
            SubscribedTypeEnum::ZcFrame => ZcFrame::parsers(),
        }
    }
}

pub enum TrackedTypeEnum {
    Connection(Box<connection::TrackedConnection>),
    ConnectionFrame(Box<connection_frame::TrackedConnectionFrame>),
    DnsTransaction(Box<dns_transaction::TrackedDns>),
    Frame(Box<frame::TrackedFrame>),
    HttpTransaction(Box<http_transaction::TrackedHttp>),
    QuicStream(Box<quic_stream::TrackedQuic>),
    TlsHandshake(Box<tls_handshake::TrackedTls>),
    ZcFrame(Box<zc_frame::TrackedZcFrame>),
}

pub struct TrackedWrapper {
    tracked: Vec<Box<TrackedTypeEnum>>,
}

/// Represents a generic subscribable type. All subscribable types must implement this trait.
pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;

    /// Returns the subscription level.
    fn level() -> Level;

    /// Returns a list of protocol parsers required to parse the subscribable type.
    fn parsers() -> Vec<ConnParser>;

    /// Process a single incoming packet.
    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) where
        Self: Sized;
}

/// Tracks subscribable types throughout the duration of a connection.
pub trait Trackable {
    type Subscribed: Subscribable<Tracked = Self>;

    /// Create a new Trackable type to manage subscription data for the duration of the connection
    /// represented by `five_tuple`.
    fn new(five_tuple: FiveTuple) -> Self;

    /// Update tracked subscription data prior to a full filter match.
    fn pre_match(&mut self, pdu: L4Pdu, session_id: Option<usize>);

    /// Update tracked subscription data on a full filter match.
    fn on_match<F>(&mut self, session: Session, callback: F)
        where F: Fn(&dyn Any);

    /// Update tracked subscription data after a full filter match.
    fn post_match<F>(&mut self, pdu: L4Pdu, callback: F)
        where F: Fn(&dyn Any);

    /// Update tracked subscription data on connection termination.
    fn on_terminate<F>(&mut self, callback: F)
        where F: Fn(&dyn Any);
}

/// A request for a callback on a subset of traffic specified by the filter.
#[doc(hidden)]
pub struct Subscription {
    packet_filter: PacketFilterFn,
    conn_filter: ConnFilterFn,
    session_filter: SessionFilterFn,
    #[cfg(feature = "timing")]
    pub(crate) timers: Timers,
}

impl Subscription {
    /// Creates a new subscription from a filter and a callback.
    pub(crate) fn new(factory: FilterFactory) -> Self {
        Subscription {
            packet_filter: factory.packet_filter,
            conn_filter: factory.conn_filter,
            session_filter: factory.session_filter,
            #[cfg(feature = "timing")]
            timers: Timers::new(),
        }
    }

    /// Invokes the software packet filter.
    pub(crate) fn filter_packet(&self, mbuf: &Mbuf) -> FilterResult {
        (self.packet_filter)(mbuf)
    }

    /// Invokes the connection filter.
    pub(crate) fn filter_conn(&self, conn: &ConnData) -> FilterResult {
        (self.conn_filter)(conn)
    }

    /// Invokes the application-layer session filter. The `idx` parameter is the numerical ID of the
    /// session.
    pub(crate) fn filter_session(&self, session: &Session, idx: usize) -> bool {
        (self.session_filter)(session, idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscribable_wrapper() {

    }
}