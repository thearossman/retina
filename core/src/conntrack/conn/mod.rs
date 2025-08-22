//! State management for connections.
//!
//! Tracks a TCP or UDP connection, performs stream reassembly, and manages protocol parser state
//! throughout the duration of the connection.

pub(crate) mod conn_info;
pub(crate) mod tcp_conn;
pub(crate) mod udp_conn;

use self::conn_info::{ConnInfo, ConnState};
use self::tcp_conn::TcpConn;
use self::udp_conn::UdpConn;
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::filter::FilterResult;
use crate::protocols::packet::tcp::{ACK, RST, SYN};
use crate::protocols::stream::ParserRegistry;
use crate::subscription::*;

use anyhow::{bail, Result};
use std::time::Instant;

/// Tracks either a TCP or a UDP connection.
///
/// Performs light-weight stream reassembly for TCP connections and tracks UDP connections.
pub(crate) enum L4Conn {
    Tcp(TcpConn),
    Udp(UdpConn),
}

/// Connection state.
pub(crate) struct Conn {
    /// Timestamp of the last observed packet in the connection.
    pub(crate) last_seen_ts: Instant,
    /// Amount of time (in milliseconds) before the connection should be expired for inactivity.
    pub(crate) inactivity_window: usize,
    /// Layer-4 connection tracking.
    pub(crate) l4conn: L4Conn,
    /// Connection information for filtering and parsing.
    pub(crate) info: ConnInfo,
}

impl Conn {
    /// Creates a new TCP connection from `ctxt` with an initial inactivity window of
    /// `initial_timeout` and a maximum out-or-order tolerance of `max_ooo`. This means that there
    /// can be at most `max_ooo` packets buffered out of sequence before Retina chooses to discard
    /// the connection.
    pub(super) fn new_tcp(
        ctxt: L4Context,
        initial_timeout: usize,
        max_ooo: usize,
        pkt_filter_results: Vec<FilterResult>,
        subscriptions: &SubscriptionData,
    ) -> Result<Self> {
        let five_tuple = FiveTuple::from_ctxt(ctxt);
        let tcp_conn = if ctxt.flags & SYN != 0 && ctxt.flags & ACK == 0 && ctxt.flags & RST == 0 {
            TcpConn::new_on_syn(ctxt, max_ooo)
        } else {
            bail!("Not SYN")
        };
        Ok(Conn {
            last_seen_ts: Instant::now(),
            inactivity_window: initial_timeout,
            l4conn: L4Conn::Tcp(tcp_conn),
            info: ConnInfo::new(five_tuple, subscriptions, pkt_filter_results),
        })
    }

    /// Creates a new UDP connection from `ctxt` with an initial inactivity window of
    /// `initial_timeout`.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn new_udp(
        ctxt: L4Context,
        initial_timeout: usize,
        pkt_filter_results: Vec<FilterResult>,
        subscriptions: &SubscriptionData,
    ) -> Result<Self> {
        let five_tuple = FiveTuple::from_ctxt(ctxt);
        let udp_conn = UdpConn;
        Ok(Conn {
            last_seen_ts: Instant::now(),
            inactivity_window: initial_timeout,
            l4conn: L4Conn::Udp(udp_conn),
            info: ConnInfo::new(five_tuple, subscriptions, pkt_filter_results),
        })
    }

    /// Updates a connection on the arrival of a new packet.
    pub(super) fn update(
        &mut self,
        pdu: L4Pdu,
        subscriptions: &SubscriptionData,
        registry: &ParserRegistry,
    ) {
        match &mut self.l4conn {
            L4Conn::Tcp(tcp_conn) => {
                if self.info.state == ConnState::Tracking {
                    if tcp_conn.ctos.ooo_buf.len() != 0 {
                        tcp_conn.ctos.ooo_buf.buf.clear();
                    }
                    if tcp_conn.stoc.ooo_buf.len() != 0 {
                        tcp_conn.stoc.ooo_buf.buf.clear();
                    }
                    tcp_conn.update_term_condition(pdu.flags(), pdu.dir);
                    self.info.sdata.post_match(&pdu, &subscriptions.callbacks);
                } else {
                    tcp_conn.reassemble(pdu, &mut self.info, subscriptions, registry);
                }
            }
            L4Conn::Udp(_udp_conn) => self.info.consume_pdu(pdu, subscriptions, registry),
        }
    }

    /// Returns the connection 5-tuple.
    pub(super) fn five_tuple(&self) -> FiveTuple {
        self.info.cdata.five_tuple
    }

    /// Returns the connection state.
    pub(super) fn state(&self) -> ConnState {
        self.info.state
    }

    /// Returns `true` if the connection has been naturally terminated.
    pub(super) fn terminated(&self) -> bool {
        match &self.l4conn {
            L4Conn::Tcp(tcp_conn) => tcp_conn.is_terminated(),
            L4Conn::Udp(_udp_conn) => false,
        }
    }

    /// Returns the `true` if the packet represented by `ctxt` is in the direction of originator ->
    /// responder.
    pub(super) fn packet_dir(&self, ctxt: &L4Context) -> bool {
        self.five_tuple().orig == ctxt.src
    }

    /// Invokes connection termination tasks that are triggered when any of the following conditions
    /// occur:
    /// - the connection naturally terminates (e.g., FIN/RST)
    /// - the connection expires due to inactivity
    /// - the connection is drained at the end of the run
    pub(crate) fn terminate(&mut self, subscription: &SubscriptionData) {
        match self.info.state {
            ConnState::Probing => {
                if subscription
                    .filters
                    .conn_filter(&self.info.cdata, &mut self.info.sdata)
                {
                    self.info.sdata.on_terminate(&subscription.callbacks);
                }
            }
            ConnState::Parsing => {
                // only call on_terminate() if the first session in the connection was matched
                let mut first_session_matched = false;
                for session in self.info.cdata.conn_parser.drain_sessions() {
                    if subscription
                        .filters
                        .session_filter(&session, &mut self.info.sdata)
                    {
                        if session.id == 0 {
                            first_session_matched = true;
                        }
                        self.info.sdata.on_match(session, &subscription.callbacks);
                    }
                }
                if first_session_matched {
                    self.info.sdata.on_terminate(&subscription.callbacks);
                }
            }
            ConnState::Tracking => {
                self.info.sdata.on_terminate(&subscription.callbacks);
            }
            ConnState::Remove | ConnState::Dropped => {
                // do nothing
            }
        }
    }
}
