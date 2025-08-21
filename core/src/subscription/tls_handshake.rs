//! TLS handshakes.
//!
//! This is a session-level subscription that delivers parsed TLS handshakes and associated
//! connection metadata. Only the first TLS handshake in a connection is parsed; subsequent
//! encrypted messages are dropped.
//!
//! ## Example
//! Prints the chosen cipher suite of TLS handshakes with `calendar.google.com`.
//! ```
//! #[filter("tls.sni = 'calendar.google.com'")]
//! fn main() {
//!     let config = default_config();
//!     let cb = |tls: TlsHandshake| {
//!         println!("{}", tls.data.cipher());
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//! }

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::tls::{parser::TlsParser, Tls};
use crate::protocols::stream::{ConnParser, Session, SessionData};
use crate::subscription::{Level, Subscribable, Trackable};

use serde::Serialize;

use std::net::SocketAddr;

use super::SubscribedData;

/// A parsed TLS handshake and connection metadata.
#[derive(Debug, Serialize)]
pub struct TlsHandshake {
    /// Connection 5-tuple.
    pub five_tuple: FiveTuple,
    /// Parsed TLS handshake data.
    pub data: Tls,
}

impl TlsHandshake {
    /// Returns the client's socket address.
    #[inline]
    pub fn client(&self) -> SocketAddr {
        self.five_tuple.orig
    }

    /// Returns the server's socket address.
    #[inline]
    pub fn server(&self) -> SocketAddr {
        self.five_tuple.resp
    }
}

use std::any::Any;
impl SubscribedData for TlsHandshake {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct TlsHandshakeWrapper;

impl Subscribable for TlsHandshakeWrapper {
    type Tracked = TrackedTls;
    type SubscribedData = TlsHandshake;

    fn level() -> Level {
        Level::Session
    }

    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Tls(TlsParser::default())]
    }
}

/// Represents TLS connection's state during the connection lifetime.
///
/// ## Remarks
/// Retina uses an internal parser to track and filter application-layer protocols, and transfers
/// session ownership to the subscription to invoke the callback on a filter match. This is an
/// optimization to avoid double-parsing: once for the filter and once for the subscription data.
/// This is why most `Trackable` trait methods for this type are unimplemented.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedTls {
    five_tuple: FiveTuple,
}

impl Trackable for TrackedTls {
    type Subscribed = TlsHandshakeWrapper;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedTls { five_tuple }
    }

    fn pre_match(&mut self, _pdu: L4Pdu, _session_id: Option<usize>) {}

    fn on_match(&mut self, session: Session, callback: &Box<dyn Fn(&dyn SubscribedData)>) {
        if let SessionData::Tls(tls) = session.data {
            let tls = TlsHandshake {
                five_tuple: self.five_tuple.clone(),
                data: *tls,
            };
            callback(&tls);
        }
    }

    fn post_match(&mut self, _pdu: L4Pdu, _callback: &Box<dyn Fn(&dyn SubscribedData)>) {}

    fn on_terminate(&mut self, _callback: &Box<dyn Fn(&dyn SubscribedData)>) {}
}
