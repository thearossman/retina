//! Connection packet stream.
//!
//! This is a connection-level subscription that provides a stream of raw Ethernet frames associated
//! with connections that satisfy the subscription filter in the order of arrival. The callback is
//! invoked once per frame.
//!
//! ## Example
//! Prints raw packet data from TLS connections on TCP/443 with subdomains of `google.com`:
//! ```
//! #[filter("tcp.port = 443 and tls.sni ~ 'google\\.com$'")]
//! fn main() {
//!     let config = default_config();
//!     let cb = |frame: ConnectionFrame| {
//!         println!("{:?}", frame.data);
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//! }
//! ```
//!
//! ## Remarks
//! The first few packets in the connection may be delivered in sequence order if the subscription's
//! filter requires Retina to reassemble the stream. Once the filter is satisfied, all remaining
//! packets in the connection are delivered in the order of observation.
// TODO: find a workaround for this, perhaps timestamping all packets by default.

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Trackable};

use std::net::SocketAddr;

use super::SubscribedData;

/// Ethernet frames in a TCP or UDP connection.
#[derive(Debug, Clone)]
pub struct ConnectionFrame {
    pub five_tuple: FiveTuple,
    pub data: Vec<u8>,
}

impl ConnectionFrame {
    /// Creates a new `ConnectionFrame`.
    pub(crate) fn new(five_tuple: FiveTuple, mbuf: &Mbuf) -> Self {
        ConnectionFrame {
            five_tuple,
            data: mbuf.data().to_vec(),
        }
    }

    /// Returns the associated connection originator's socket address.
    #[inline]
    pub fn client(&self) -> SocketAddr {
        self.five_tuple.orig
    }

    /// Returns the associated connection responder's socket address.
    #[inline]
    pub fn server(&self) -> SocketAddr {
        self.five_tuple.resp
    }
}

impl SubscribedData for ConnectionFrame {}

pub struct ConnectionFrameWrapper {}

impl Subscribable for ConnectionFrameWrapper {
    type Tracked = TrackedConnectionFrame;
    type SubscribedData = ConnectionFrame;

    fn level() -> Level {
        Level::Connection
    }

    fn parsers() -> Vec<ConnParser> {
        vec![]
    }
}

/// Tracks connection frames throughout the duration of the connection lifetime.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedConnectionFrame {
    /// Connection 5-tuple.
    five_tuple: FiveTuple,
    /// Buffers packets in the connection prior to a filter match.
    buf: Vec<ConnectionFrame>,
}

impl Trackable for TrackedConnectionFrame {
    type Subscribed = ConnectionFrameWrapper;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedConnectionFrame {
            five_tuple,
            buf: vec![],
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.buf
            .push(ConnectionFrame::new(self.five_tuple, pdu.mbuf_ref()));
    }

    fn on_match(&mut self, _session: Session, callback: &Box<dyn Fn(&dyn SubscribedData)>) {
        self.buf.drain(..).for_each(|frame| {
            callback(&frame);
        });
    }

    fn post_match(&mut self, pdu: L4Pdu, callback: &Box<dyn Fn(&dyn SubscribedData)>) {
        callback(&ConnectionFrame::new(self.five_tuple, pdu.mbuf_ref()));
    }

    fn on_terminate(&mut self, callback: &Box<dyn Fn(&dyn SubscribedData)>) {
        self.buf.drain(..).for_each(|frame| {
            callback(&frame);
        });
    }
}
