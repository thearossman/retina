use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::filter::FilterResult;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::protocols::stream::{
    ConnData, ParseResult, ParserRegistry, ProbeRegistryResult, Session,
};
use crate::subscription::*;

// #[derive(Debug)]
pub(crate) struct ConnInfo {
    /// State of Conn
    pub(crate) state: ConnState,
    /// Connection data (for filtering)
    pub(crate) cdata: ConnData,
    /// Subscription data (for delivering)
    pub(crate) sdata: TrackableTypes,
}

impl ConnInfo {
    pub(super) fn new(
        five_tuple: FiveTuple,
        subscriptions: &SubscriptionData,
        pkt_term_nodes: Vec<FilterResult>,
    ) -> Self {
        ConnInfo {
            state: ConnState::Probing,
            cdata: ConnData::new(five_tuple, 0),
            sdata: TrackableTypes::new(five_tuple, &subscriptions.subscribable, pkt_term_nodes),
        }
    }

    pub(crate) fn consume_pdu(
        &mut self,
        pdu: L4Pdu,
        subscriptions: &SubscriptionData,
        registry: &ParserRegistry,
    ) {
        match self.state {
            ConnState::Probing => {
                self.on_probe(pdu, subscriptions, registry);
            }
            ConnState::Parsing => {
                self.on_parse(pdu, subscriptions);
            }
            ConnState::Tracking => {
                self.on_track(pdu, subscriptions);
            }
            ConnState::Remove | ConnState::Dropped => {
                drop(pdu);
            }
        }
    }

    fn on_probe(
        &mut self,
        pdu: L4Pdu,
        subscriptions: &SubscriptionData,
        registry: &ParserRegistry,
    ) {
        match registry.probe_all(&pdu) {
            ProbeRegistryResult::Some(conn_parser) => {
                self.cdata.conn_parser = conn_parser;
                let matches = subscriptions
                    .filters
                    .conn_filter(&self.cdata, &mut self.sdata);
                if matches {
                    self.state = ConnState::Parsing;
                    self.on_parse(pdu, subscriptions);
                } else {
                    self.state = self.get_drop_state();
                }
            }
            ProbeRegistryResult::None => {
                // conn_parser remains Unknown
                self.sdata.pre_match(&pdu, None);
                let matches = subscriptions
                    .filters
                    .conn_filter(&self.cdata, &mut self.sdata);
                if !matches {
                    self.state = self.get_drop_state();
                } else {
                    if self
                        .sdata
                        .conn_filter_results
                        .iter()
                        .any(|r| matches!(r, FilterResult::MatchTerminal(_)))
                    {
                        self.sdata
                            .on_match(Session::default(), &subscriptions.callbacks);
                        self.state = self.get_match_state(0, subscriptions);
                    } else {
                        self.state = self.get_drop_state();
                    }
                }
            }
            ProbeRegistryResult::Unsure => {
                self.sdata.pre_match(&pdu, None);
            }
        }
    }

    fn on_parse(&mut self, pdu: L4Pdu, subscriptions: &SubscriptionData) {
        match self.cdata.conn_parser.parse(&pdu) {
            ParseResult::Done(id) => {
                self.sdata.pre_match(&pdu, Some(id));
                if let Some(session) = self.cdata.conn_parser.remove_session(id) {
                    let matched = subscriptions
                        .filters
                        .session_filter(&session, &mut self.sdata);
                    if matched {
                        self.sdata.on_match(session, &subscriptions.callbacks);
                        self.state = self.get_match_state(id, subscriptions);
                    } else {
                        self.state = self.get_nomatch_state(id, subscriptions);
                    }
                } else {
                    log::error!("Done parse but no mru");
                    self.state = self.get_drop_state();
                }
            }
            ParseResult::Continue(id) => {
                self.sdata.pre_match(&pdu, Some(id));
            }
            ParseResult::Skipped => {
                self.sdata.pre_match(&pdu, None);
            }
        }
    }

    fn on_track(&mut self, pdu: L4Pdu, subscriptions: &SubscriptionData) {
        self.sdata.post_match(&pdu, &subscriptions.callbacks);
    }

    fn get_match_state(&self, session_id: usize, subscriptions: &SubscriptionData) -> ConnState {
        if session_id == 0 && subscriptions.subscribable.level() == Level::Connection {
            ConnState::Tracking
        } else {
            self.cdata.conn_parser.session_match_state()
        }
    }

    fn get_nomatch_state(&self, session_id: usize, subscriptions: &SubscriptionData) -> ConnState {
        if session_id == 0 && subscriptions.subscribable.level() == Level::Connection {
            self.get_drop_state()
        } else {
            self.cdata.conn_parser.session_nomatch_state()
        }
    }

    fn get_drop_state(&self) -> ConnState {
        if self.cdata.five_tuple.proto == UDP_PROTOCOL {
            return ConnState::Dropped;
        }
        ConnState::Remove
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnState {
    /// Unknown application-layer protocol, needs probing.
    Probing,
    /// Known application-layer protocol, needs parsing.
    Parsing,
    /// No need to probe or parse, just track. Application-layer protocol may or may not be known.
    Tracking,
    /// Connection will be removed
    Remove,
    /// Unmatched UDP connection; waiting to be aged out by timerwheel.
    /// Prevents dropped UDP conns from being re-inserted in table
    Dropped,
}
