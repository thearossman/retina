//! DNS transactions.
//!
//! This is a session-level subscription that delivers parsed DNS transaction records and associated
//! connection metadata.
//!
//! ## Example
//! Prints DNS domain name queries to `8.8.8.8`:
//! ```
//! #[filter("ipv4.addr = 8.8.8.8")]
//! fn main() {
//!     let config = default_config();
//!     let cb = |dns: DnsTransaction| {
//!         println!("{}", dns.data.query_domain());
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//! }

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::dns::{parser::DnsParser, Dns};
use crate::protocols::stream::{ConnParser, Session, SessionData};
use crate::subscription::{Level, Subscribable, Trackable};

use serde::Serialize;

use std::net::SocketAddr;

use super::SubscribedData;

/// A parsed DNS transaction and connection metadata.
#[derive(Debug, Serialize)]
pub struct DnsTransaction {
    pub five_tuple: FiveTuple,
    pub data: Dns,
}

impl DnsTransaction {
    /// Returns the DNS resolver's socket address.
    #[inline]
    pub fn client(&self) -> SocketAddr {
        self.five_tuple.orig
    }

    /// Returns the DNS server's socket address.
    #[inline]
    pub fn server(&self) -> SocketAddr {
        self.five_tuple.resp
    }
}

pub struct DnsTransactionWrapper;

impl Subscribable for DnsTransactionWrapper {
    type Tracked = TrackedDns;

    fn level() -> Level {
        Level::Session
    }

    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Dns(DnsParser::default())]
    }
}

/// Represents a DNS connection's during the connection lifetime.
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
pub struct TrackedDns {
    five_tuple: FiveTuple,
}

impl TrackedDns {}

impl Trackable for TrackedDns {
    type Subscribed = DnsTransactionWrapper;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedDns { five_tuple }
    }

    fn pre_match(&mut self, _pdu: &L4Pdu, _session_id: Option<usize>) {}

    fn on_match(&mut self, session: Session, callback: &Box<dyn Fn(SubscribedData)>) {
        if let SessionData::Dns(dns) = session.data {
            callback(SubscribedData::DnsTransaction(DnsTransaction {
                five_tuple: self.five_tuple,
                data: *dns,
            }));
        }
    }

    fn post_match(&mut self, _pdu: &L4Pdu, _callback: &Box<dyn Fn(SubscribedData)>) {}

    fn on_terminate(&mut self, _callback: &Box<dyn Fn(SubscribedData)>) {}
}
