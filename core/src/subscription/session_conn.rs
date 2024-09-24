
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session};
use crate::protocols::stream::{tls::parser::TlsParser, quic::parser::QuicParser,
                               dns::parser::DnsParser, http::parser::HttpParser};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

use std::time::Duration;
use super::connection::{Connection, TrackedConnection};

pub struct SessionConn {
    pub five_tuple: FiveTuple,
    pub conn: Connection,
    pub sessions: Vec<Session>
}

impl Subscribable for SessionConn {
    type Tracked = TrackedSessionConn;

    fn level() -> Level {
        Level::Connection
    }

    fn parsers() -> Vec<ConnParser> {
        vec![
            ConnParser::Tls(TlsParser::default()),
            ConnParser::Quic(QuicParser::default()),
            ConnParser::Dns(DnsParser::default()),
            ConnParser::Http(HttpParser::default()),
        ]
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

pub struct TrackedSessionConn {
    five_tuple: FiveTuple,
    conn: TrackedConnection,
    sessions: Vec<Session>,
}


impl Trackable for TrackedSessionConn {
    type Subscribed = SessionConn;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedSessionConn {
            five_tuple,
            conn: TrackedConnection::new(five_tuple),
            sessions: vec![],
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.conn.update(pdu);
    }

    fn on_match(&mut self, session: Session, _subscription: &Subscription<Self::Subscribed>) {
        self.sessions.push(session);
    }

    fn post_match(&mut self, pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {
        self.conn.update(pdu);
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        let (duration, max_inactivity, time_to_second_packet) =
            if self.conn.ctos.nb_pkts + self.conn.stoc.nb_pkts == 1 {
                (
                    Duration::default(),
                    Duration::default(),
                    Duration::default(),
                )
            } else {
                (
                    self.conn.last_seen_ts - self.conn.first_seen_ts,
                    self.conn.max_inactivity,
                    self.conn.second_seen_ts - self.conn.first_seen_ts,
                )
            };

        let conn = Connection {
            five_tuple: self.five_tuple,
            ts: self.conn.first_seen_ts,
            duration,
            max_inactivity,
            time_to_second_packet,
            history: self.conn.history.clone(),
            orig: self.conn.ctos.clone(),
            resp: self.conn.stoc.clone(),
        };

        subscription.invoke(
            SessionConn {
                five_tuple: self.five_tuple,
                conn,
                sessions: std::mem::take(&mut self.sessions),
            }
        );
    }
}
