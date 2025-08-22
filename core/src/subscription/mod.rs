//! Subscribable data types.
//!
//! A subscription is a request for a callback on a subset of network traffic specified by a filter.
//! Callback functions are implemented as a closure that takes a subscribable data type as the
//! parameter and immutably borrows values from the environment. Built-in subscribable types can
//! be customized within the framework to provide additional data to the callback if needed.

pub mod connection;
pub mod connection_frame;
pub mod dns_transaction;
// pub mod frame;
pub mod http_transaction;
pub mod quic_stream;
pub mod tls_handshake;
// pub mod zc_frame;

// pub mod wrappers;

// Re-export subscribable types for more convenient usage.
pub use self::connection::Connection;
pub use self::connection_frame::ConnectionFrame;
pub use self::dns_transaction::DnsTransaction;
// pub use self::frame::Frame;
pub use self::http_transaction::HttpTransaction;
pub use self::quic_stream::QuicStream;
pub use self::tls_handshake::TlsHandshake;
// pub use self::zc_frame::ZcFrame;

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
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

/// Represents a generic subscribable type. All subscribable types must implement this trait.
pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;

    /// Returns the subscription level.
    fn level() -> Level;

    /// Returns a list of protocol parsers required to parse the subscribable type.
    fn parsers() -> Vec<ConnParser>;
}

/// Tracks subscribable types throughout the duration of a connection.
pub trait Trackable {
    type Subscribed: Subscribable<Tracked = Self>;

    /// Create a new Trackable type to manage subscription data for the duration of the connection
    /// represented by `five_tuple`.
    fn new(five_tuple: FiveTuple) -> Self;

    /// Update tracked subscription data prior to a full filter match.
    fn pre_match(&mut self, pdu: &L4Pdu, session_id: Option<usize>);

    /// Update tracked subscription data on a full filter match.
    fn on_match(&mut self, session: Session, callback: &Box<dyn Fn(SubscribedData)>);

    /// Update tracked subscription data after a full filter match.
    fn post_match(&mut self, pdu: &L4Pdu, callback: &Box<dyn Fn(SubscribedData)>);

    /// Update tracked subscription data on connection termination.
    fn on_terminate(&mut self, callback: &Box<dyn Fn(SubscribedData)>);
}

pub struct SubscriptionData {
    pub callbacks: SubscribedCallbacks,
    pub subscribable: SubscribableTypes,
    pub filters: Filters,
}

impl SubscriptionData {
    pub(crate) fn process_packet(&self, mbuf: Mbuf, conn_tracker: &mut ConnTracker) {
        let results = self.filters.packet_filter(&mbuf);
        if results.iter().any(|r| {
            matches!(
                r,
                FilterResult::MatchNonTerminal(_) | FilterResult::MatchTerminal(_)
            )
        }) {
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                conn_tracker.process(mbuf, ctxt, self, results);
            } else {
                drop(mbuf);
            }
        }
    }
}

pub struct SubscribedCallbacks {
    pub callbacks: Vec<Box<dyn Fn(SubscribedData)>>,
}

pub struct SubscribableTypes {
    pub subscriptions: Vec<SubscribableTypeId>,
}

pub struct Filters {
    pub filters: Vec<FilterFactory>,
}

impl Filters {
    pub fn new(filters: Vec<FilterFactory>) -> Self {
        Filters { filters }
    }

    pub fn packet_filter(&self, mbuf: &Mbuf) -> Vec<FilterResult> {
        self.filters
            .iter()
            .map(|f| (f.packet_filter)(mbuf))
            .collect()
    }

    pub fn conn_filter(&self, conn: &ConnData, trackable: &mut TrackableTypes) -> bool {
        let results = self
            .filters
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let last_result = &trackable.pkt_filter_results.get(i).unwrap();
                match last_result {
                    FilterResult::MatchTerminal(idx) => (f.conn_filter)(conn, *idx),
                    FilterResult::MatchNonTerminal(idx) => (f.conn_filter)(conn, *idx),
                    _ => FilterResult::NoMatch,
                }
            })
            .collect();
        trackable.conn_filter_results = results;
        trackable.conn_filter_results.iter().any(|r| {
            matches!(
                r,
                FilterResult::MatchTerminal(_) | FilterResult::MatchNonTerminal(_)
            )
        })
    }

    pub fn session_filter(&self, session: &Session, trackable: &mut TrackableTypes) -> bool {
        self.filters
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let last_result = &trackable.conn_filter_results.get(i).unwrap();
                match last_result {
                    FilterResult::MatchTerminal(node) => {
                        *trackable.session_filter_results.get_mut(i).unwrap() =
                            (f.session_filter)(session, *node);
                        *trackable.session_filter_results.get(i).unwrap()
                    }
                    FilterResult::MatchNonTerminal(node) => {
                        *trackable.session_filter_results.get_mut(i).unwrap() =
                            (f.session_filter)(session, *node);
                        *trackable.session_filter_results.get(i).unwrap()
                    }
                    FilterResult::NoMatch => false,
                }
            })
            .collect::<Vec<_>>()
            .iter()
            .any(|r| *r)
    }
}

impl SubscribableTypes {
    pub fn level(&self) -> Level {
        let levels = self
            .subscriptions
            .iter()
            .map(|s| s.level())
            .collect::<Vec<_>>();
        if levels.iter().any(|l| *l == Level::Connection) {
            Level::Connection
        } else if levels.iter().any(|l| *l == Level::Session) {
            Level::Session
        } else {
            Level::Packet
        }
    }

    pub fn parsers(&self) -> Vec<ConnParser> {
        let mut parser_strs = Vec::new();
        for subscription in &self.subscriptions {
            for parser in subscription.parsers() {
                let parser_str = parser.name();
                if !parser_strs.contains(&parser_str) {
                    parser_strs.push(parser_str);
                }
            }
        }
        parser_strs
            .iter()
            .map(|s| ConnParser::from_name(s).unwrap())
            .collect()
    }
}

pub struct TrackableTypes {
    pub tracked: Vec<TrackableType>,
    pub pkt_filter_results: Vec<FilterResult>,
    pub conn_filter_results: Vec<FilterResult>,
    pub session_filter_results: Vec<bool>,
}

impl TrackableTypes {
    pub fn new(
        five_tuple: FiveTuple,
        subscriptions: &SubscribableTypes,
        pkt_filter_results: Vec<FilterResult>,
    ) -> Self {
        TrackableTypes {
            tracked: subscriptions
                .subscriptions
                .iter()
                .map(|s| s.new_tracked(&five_tuple))
                .collect(),
            pkt_filter_results: pkt_filter_results,
            conn_filter_results: vec![FilterResult::NoMatch; subscriptions.subscriptions.len()],
            session_filter_results: vec![false; subscriptions.subscriptions.len()],
        }
    }

    pub fn pre_match(&mut self, pdu: &L4Pdu, session_id: Option<usize>) {
        for tracked in &mut self.tracked {
            tracked.pre_match(pdu, session_id);
        }
    }

    pub fn on_match(&mut self, session: Session, callbacks: &SubscribedCallbacks) {
        for (i, tracked) in self.tracked.iter_mut().enumerate() {
            if !matches!(
                self.conn_filter_results.get(i).unwrap(),
                FilterResult::MatchTerminal(_)
            ) && !self.session_filter_results.get(i).unwrap()
            {
                continue;
            }
            tracked.on_match(session.clone(), &callbacks.callbacks.get(i).unwrap());
        }
    }

    pub fn post_match(&mut self, pdu: &L4Pdu, callbacks: &SubscribedCallbacks) {
        for (i, tracked) in &mut self.tracked.iter_mut().enumerate() {
            if !matches!(
                self.conn_filter_results.get(i).unwrap(),
                FilterResult::MatchTerminal(_)
            ) && !self.session_filter_results.get(i).unwrap()
            {
                continue;
            }
            tracked.post_match(pdu, &callbacks.callbacks.get(i).unwrap());
        }
    }

    pub fn on_terminate(&mut self, callbacks: &SubscribedCallbacks) {
        for (i, tracked) in &mut self.tracked.iter_mut().enumerate() {
            tracked.on_terminate(&callbacks.callbacks.get(i).unwrap());
        }
    }
}

// This is a gross workaround to make the naive solution work.
// We can't do a vector of `dyn` subscribable types, because of the
// subscribable associated types.
#[derive(Clone, Debug)]
pub enum SubscribableTypeId {
    Connection,
    ConnectionFrame,
    DnsTransaction,
    // Frame,
    HttpTransaction,
    QuicStream,
    TlsHandshake,
    // ZcFrame,
}

impl SubscribableTypeId {
    /// Returns the level of the subscribable type.
    pub fn level(&self) -> Level {
        match self {
            SubscribableTypeId::Connection => connection::ConnectionWrapper::level(),
            SubscribableTypeId::ConnectionFrame => {
                connection_frame::ConnectionFrameWrapper::level()
            }
            SubscribableTypeId::DnsTransaction => dns_transaction::DnsTransactionWrapper::level(),
            // SubscribableTypeId::Frame => Frame::level(),
            SubscribableTypeId::HttpTransaction => {
                http_transaction::HttpTransactionWrapper::level()
            }
            SubscribableTypeId::QuicStream => quic_stream::QuicStreamWrapper::level(),
            SubscribableTypeId::TlsHandshake => tls_handshake::TlsHandshakeWrapper::level(),
            // SubscribableTypeId::ZcFrame => ZcFrame::level(),
        }
    }

    pub fn parsers(&self) -> Vec<ConnParser> {
        match self {
            SubscribableTypeId::Connection => connection::ConnectionWrapper::parsers(),
            SubscribableTypeId::ConnectionFrame => {
                connection_frame::ConnectionFrameWrapper::parsers()
            }
            SubscribableTypeId::DnsTransaction => dns_transaction::DnsTransactionWrapper::parsers(),
            // SubscribableTypeId::Frame => Frame::parsers(),
            SubscribableTypeId::HttpTransaction => {
                http_transaction::HttpTransactionWrapper::parsers()
            }
            SubscribableTypeId::QuicStream => quic_stream::QuicStreamWrapper::parsers(),
            SubscribableTypeId::TlsHandshake => tls_handshake::TlsHandshakeWrapper::parsers(),
            // SubscribableTypeId::ZcFrame => ZcFrame::parsers(),
        }
    }

    pub fn new_tracked(&self, five_tuple: &FiveTuple) -> TrackableType {
        match self {
            SubscribableTypeId::Connection => TrackableType::Connection(
                <connection::ConnectionWrapper as Subscribable>::Tracked::new(*five_tuple),
            ),
            SubscribableTypeId::ConnectionFrame => TrackableType::ConnectionFrame(
                <connection_frame::ConnectionFrameWrapper as Subscribable>::Tracked::new(
                    *five_tuple,
                ),
            ),
            SubscribableTypeId::DnsTransaction => TrackableType::DnsTransaction(
                <dns_transaction::DnsTransactionWrapper as Subscribable>::Tracked::new(*five_tuple),
            ),
            // SubscribableTypeId::Frame => {
            //     TrackableType::Frame(<Frame as Subscribable>::Tracked::new(*five_tuple))
            // }
            SubscribableTypeId::HttpTransaction => TrackableType::HttpTransaction(
                <http_transaction::HttpTransactionWrapper as Subscribable>::Tracked::new(
                    *five_tuple,
                ),
            ),
            SubscribableTypeId::QuicStream => TrackableType::QuicStream(
                <quic_stream::QuicStreamWrapper as Subscribable>::Tracked::new(*five_tuple),
            ),
            SubscribableTypeId::TlsHandshake => TrackableType::TlsHandshake(
                <tls_handshake::TlsHandshakeWrapper as Subscribable>::Tracked::new(*five_tuple),
            ),
            // SubscribableTypeId::ZcFrame => {
            //     TrackableType::ZcFrame(<ZcFrame as Subscribable>::Tracked::new(*five_tuple))
            // }
        }
    }
}

pub enum TrackableType {
    Connection(connection::TrackedConnection),
    ConnectionFrame(connection_frame::TrackedConnectionFrame),
    DnsTransaction(dns_transaction::TrackedDns),
    // Frame(frame::TrackedFrame),
    HttpTransaction(http_transaction::TrackedHttp),
    QuicStream(quic_stream::TrackedQuic),
    TlsHandshake(tls_handshake::TrackedTls),
    // ZcFrame(zc_frame::TrackedZcFrame),
}

impl TrackableType {
    pub fn pre_match(&mut self, pdu: &L4Pdu, session_id: Option<usize>) {
        match self {
            TrackableType::Connection(tracked) => tracked.pre_match(pdu, session_id),
            TrackableType::ConnectionFrame(tracked) => tracked.pre_match(pdu, session_id),
            TrackableType::DnsTransaction(tracked) => tracked.pre_match(pdu, session_id),
            // TrackableType::Frame(tracked) => tracked.pre_match(pdu, session_id),
            TrackableType::HttpTransaction(tracked) => tracked.pre_match(pdu, session_id),
            TrackableType::QuicStream(tracked) => tracked.pre_match(pdu, session_id),
            TrackableType::TlsHandshake(tracked) => tracked.pre_match(pdu, session_id),
            // TrackableType::ZcFrame(tracked) => tracked.pre_match(pdu, session_id),
        }
    }

    pub fn on_match(&mut self, session: Session, callback: &Box<dyn Fn(SubscribedData)>) {
        match self {
            TrackableType::Connection(tracked) => tracked.on_match(session, callback),
            TrackableType::ConnectionFrame(tracked) => tracked.on_match(session, callback),
            TrackableType::DnsTransaction(tracked) => tracked.on_match(session, callback),
            // TrackableType::Frame(tracked) => tracked.on_match(session, callback),
            TrackableType::HttpTransaction(tracked) => tracked.on_match(session, callback),
            TrackableType::QuicStream(tracked) => tracked.on_match(session, callback),
            TrackableType::TlsHandshake(tracked) => tracked.on_match(session, callback),
            // TrackableType::ZcFrame(tracked) => tracked.on_match(session, callback),
        }
    }

    pub fn post_match(&mut self, pdu: &L4Pdu, callback: &Box<dyn Fn(SubscribedData)>) {
        match self {
            TrackableType::Connection(tracked) => tracked.post_match(pdu, callback),
            TrackableType::ConnectionFrame(tracked) => tracked.post_match(pdu, callback),
            TrackableType::DnsTransaction(tracked) => tracked.post_match(pdu, callback),
            // TrackableType::Frame(tracked) => tracked.post_match(pdu, callback),
            TrackableType::HttpTransaction(tracked) => tracked.post_match(pdu, callback),
            TrackableType::QuicStream(tracked) => tracked.post_match(pdu, callback),
            TrackableType::TlsHandshake(tracked) => tracked.post_match(pdu, callback),
            // TrackableType::ZcFrame(tracked) => tracked.post_match(pdu, callback),
        }
    }

    pub fn on_terminate(&mut self, callback: &Box<dyn Fn(SubscribedData)>) {
        match self {
            TrackableType::Connection(tracked) => tracked.on_terminate(callback),
            TrackableType::ConnectionFrame(tracked) => tracked.on_terminate(callback),
            TrackableType::DnsTransaction(tracked) => tracked.on_terminate(callback),
            // TrackableType::Frame(tracked) => tracked.on_terminate(callback),
            TrackableType::HttpTransaction(tracked) => tracked.on_terminate(callback),
            TrackableType::QuicStream(tracked) => tracked.on_terminate(callback),
            TrackableType::TlsHandshake(tracked) => tracked.on_terminate(callback),
            // TrackableType::ZcFrame(tracked) => tracked.on_terminate(callback),
        }
    }
}

pub enum SubscribedData {
    Connection(Connection),
    ConnectionFrame(ConnectionFrame),
    DnsTransaction(DnsTransaction),
    // Frame(Frame),
    HttpTransaction(HttpTransaction),
    QuicStream(QuicStream),
    TlsHandshake(TlsHandshake),
    // ZcFrame(ZcFrame),
}
