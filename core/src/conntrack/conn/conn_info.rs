use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::filter::FilterResult;
use crate::protocols::stream::{
    ConnData, ParseResult, ParserRegistry, ProbeRegistryResult, Session,
};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

use regex_automata::{dfa::{Automaton, dense, sparse}, 
                     util::{start, primitives::StateID}, Anchored, PatternSet};

#[derive(Debug)]
pub(crate) struct ConnInfo<T>
where
    T: Trackable,
{
    /// State of Conn
    pub(crate) state: ConnState,
    /// Connection data (for filtering)
    pub(crate) cdata: ConnData,
    /// Subscription data (for delivering)
    pub(crate) sdata: T,
    // DFA for regex matching
    #[cfg(feature = "dense")]
    pub(crate) regex_dfa: dense::DFA<Vec<u32>>,
    #[cfg(not(feature = "dense"))]
    pub(crate) regex_dfa: sparse::DFA<Vec<u8>>,
    pub(crate) curr_state: StateID,
    pub(crate) pattern_set: PatternSet,
}

impl<T> ConnInfo<T>
where
    T: Trackable,
{  
    #[cfg(feature = "dense")]
    pub(super) fn new(five_tuple: FiveTuple, pkt_term_node: usize, 
            regex_dfa: dense::DFA<Vec<u32>>, start_state: StateID) -> Self {
        ConnInfo {
            state: ConnState::Probing,
            cdata: ConnData::new(five_tuple, pkt_term_node),
            sdata: T::new(five_tuple),
            regex_dfa,
            curr_state: start_state,
            pattern_set: PatternSet::new(regex_dfa.pattern_len())
        }
    }

    #[cfg(not(feature = "dense"))]
    pub(super) fn new(five_tuple: FiveTuple, pkt_term_node: usize, 
            regex_dfa: sparse::DFA<Vec<u8>>, start_state: StateID) -> Self {
        let pattern_set = PatternSet::new(regex_dfa.pattern_len());
        ConnInfo {
            state: ConnState::Probing,
            cdata: ConnData::new(five_tuple, pkt_term_node),
            sdata: T::new(five_tuple),
            regex_dfa,
            curr_state: start_state,
            pattern_set
        }
    }

    pub(crate) fn string_match(&mut self, pdu: &L4Pdu) {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 || self.pattern_set.is_full() {
            return;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            for b in data {
                self.curr_state = self.regex_dfa.next_state(self.curr_state, *b);
                if self.regex_dfa.is_match_state(self.curr_state) {
                    for i in 0..self.regex_dfa.match_len(self.curr_state) {
                        self.pattern_set.insert(self.regex_dfa.match_pattern(self.curr_state, i));
                    }
                }
            }
        }
    }

    pub(crate) fn consume_pdu(
        &mut self,
        pdu: L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        self.string_match(&pdu);
        match self.state {
            ConnState::Probing => {
                self.on_probe(pdu, subscription, registry);
            }
            ConnState::Parsing => {
                self.on_parse(pdu, subscription);
            }
            ConnState::Tracking => {
                self.on_track(pdu, subscription);
            }
            ConnState::Remove => {
                drop(pdu);
            }
        }
    }

    fn on_probe(
        &mut self,
        pdu: L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        match registry.probe_all(&pdu) {
            ProbeRegistryResult::Some(conn_parser) => {
                self.cdata.conn_parser = conn_parser;
                match subscription.filter_conn(&self.cdata) {
                    FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                        self.state = ConnState::Parsing;
                        self.cdata.conn_term_node = idx;
                        self.on_parse(pdu, subscription);
                    }
                    FilterResult::NoMatch => {
                        self.state = ConnState::Remove;
                    }
                }
            }
            ProbeRegistryResult::None => {
                // conn_parser remains Unknown
                self.sdata.pre_match(pdu, None);
                match subscription.filter_conn(&self.cdata) {
                    FilterResult::MatchTerminal(_idx) => {
                        self.sdata.on_match(Session::default(), subscription);
                        self.state = self.get_match_state(0);
                    }
                    FilterResult::MatchNonTerminal(_idx) => {
                        self.state = ConnState::Remove;
                    }
                    FilterResult::NoMatch => {
                        self.state = ConnState::Remove;
                    }
                }
            }
            ProbeRegistryResult::Unsure => {
                self.sdata.pre_match(pdu, None);
            }
        }
    }

    fn on_parse(&mut self, pdu: L4Pdu, subscription: &Subscription<T::Subscribed>) {
        match self.cdata.conn_parser.parse(&pdu) {
            ParseResult::Done(id) => {
                self.sdata.pre_match(pdu, Some(id));
                if let Some(session) = self.cdata.conn_parser.remove_session(id) {
                    if subscription.filter_session(&session, self.cdata.conn_term_node) {
                        self.sdata.on_match(session, subscription);
                        self.state = self.get_match_state(id);
                    } else {
                        self.state = self.get_nomatch_state(id);
                    }
                } else {
                    log::error!("Done parse but no mru");
                    self.state = ConnState::Remove;
                }
            }
            ParseResult::Continue(id) => {
                self.sdata.pre_match(pdu, Some(id));
            }
            ParseResult::Skipped => {
                self.sdata.pre_match(pdu, None);
            }
        }
    }

    fn on_track(&mut self, pdu: L4Pdu, subscription: &Subscription<T::Subscribed>) {
        self.sdata.post_match(pdu, subscription);
    }

    fn get_match_state(&self, session_id: usize) -> ConnState {
        if session_id == 0 && T::Subscribed::level() == Level::Connection {
            ConnState::Tracking
        } else {
            self.cdata.conn_parser.session_match_state()
        }
    }

    fn get_nomatch_state(&self, session_id: usize) -> ConnState {
        if session_id == 0 && T::Subscribed::level() == Level::Connection {
            ConnState::Remove
        } else {
            self.cdata.conn_parser.session_nomatch_state()
        }
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
}
