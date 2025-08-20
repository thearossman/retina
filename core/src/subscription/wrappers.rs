/* Gross wraparounds to make the parents work */

use super::*;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use std::any::Any;

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub trait WrappedSubscribable: AsAny {
    fn level(&self) -> Level;
    fn parsers(&self) -> Vec<ConnParser>;
}

pub trait WrappedTrackable: AsAny {
    fn pre_match_wrapped(&mut self, pdu: L4Pdu, session_id: Option<usize>);
    fn on_match_wrapped(&mut self, session: Session, subscription: &dyn WrappedSubscription);
    fn post_match_wrapped(&mut self, pdu: L4Pdu, subscription: &dyn WrappedSubscription);
    fn on_terminate_wrapped(&mut self, subscription: &dyn WrappedSubscription);
}

pub trait WrappedSubscription<'a>: AsAny {
    fn filter_packet(&self, mbuf: &Mbuf) -> FilterResult;
    fn filter_conn(&self, conn: &ConnData) -> FilterResult;
    fn filter_session(&self, session: &Session, idx: usize) -> bool;
    fn invoke_boxed(&self, obj: Box<dyn Any>);
}

impl<S> WrappedSubscribable for S
where
    S: Subscribable + Any,
    S::Tracked: Any + Trackable<Subscribed = S>,
{
    fn level(&self) -> Level {
        S::level()
    }
    fn parsers(&self) -> Vec<ConnParser> {
        S::parsers()
    }
}

impl<T> WrappedTrackable for T
where
    T: Trackable + Any,
    T::Subscribed: Any,
{
    fn pre_match_wrapped(&mut self, pdu: L4Pdu, session_id: Option<usize>) {
        self.pre_match(pdu, session_id)
    }
    fn on_match_wrapped(&mut self, session: Session, subscription: &dyn WrappedSubscription) {
        if let Some(sub) = subscription
            .as_any()
            .downcast_ref::<Subscription<T::Subscribed>>()
        {
            self.on_match(session, sub)
        }
    }
    fn post_match_wrapped(&mut self, pdu: L4Pdu, subscription: &dyn WrappedSubscription) {
        if let Some(sub) = subscription
            .as_any()
            .downcast_ref::<Subscription<T::Subscribed>>()
        {
            self.post_match(pdu, sub)
        }
    }
    fn on_terminate_wrapped(&mut self, subscription: &dyn WrappedSubscription) {
        if let Some(sub) = subscription
            .as_any()
            .downcast_ref::<Subscription<T::Subscribed>>()
        {
            self.on_terminate(sub)
        }
    }
}

impl<'a, S> WrappedSubscription<'a> for Subscription<'static, S>
where
    S: Subscribable + Any,
{
    fn filter_packet(&self, mbuf: &Mbuf) -> FilterResult {
        self.filter_packet(mbuf)
    }
    fn filter_conn(&self, conn: &ConnData) -> FilterResult {
        self.filter_conn(conn)
    }
    fn filter_session(&self, session: &Session, idx: usize) -> bool {
        self.filter_session(session, idx)
    }
    fn invoke_boxed(&self, obj: Box<dyn Any>) {
        if let Ok(s) = obj.downcast::<S>() {
            let s: S = *s;
            Subscription::<S>::invoke(self, s);
        }
    }
}

pub struct Subscribables {
    pub(crate) subscribables: Vec<Box<dyn WrappedSubscribable>>,
}

impl Subscribables {
    fn level(&self) -> Level {
        let levels = self
            .subscribables
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

    /// Returns a list of protocol parsers required to parse the subscribable type.
    fn parsers(&self) -> Vec<ConnParser> {
        let mut parsers = Vec::new();
        for parser in self
            .subscribables
            .iter()
            .flat_map(|s| s.parsers())
            .collect::<Vec<_>>()
        {
            let parser_name = parser.name();
            if !parsers.contains(&parser_name) {
                parsers.push(parser_name);
            }
        }
        let mut conn_parsers = Vec::new();
        for name in parsers {
            if let Some(conn_parser) = ConnParser::from_name(&name) {
                conn_parsers.push(conn_parser);
            }
        }
        conn_parsers
    }
}

pub struct Subscriptions {
    pub(crate) subscriptions: Vec<Box<dyn WrappedSubscription<'static>>>,
}

impl Subscriptions {
    fn process_packet(&self, mbuf: &Mbuf, conn_tracker: &mut ConnTracker) {
        let mut matched = false;
        let mut pkt_results = Vec::new();
        for subscription in &self.subscriptions {
            match subscription.filter_packet(&mbuf) {
                FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                    matched = true;
                    pkt_results.push(Some(idx));
                }
                _ => pkt_results.push(None),
            }
        }
        if matched {
            if let Ok(ctxt) = L4Context::new(&mbuf, 0) {
                conn_tracker.process(mbuf, ctxt, pkt_results, self);
            }
        }
    }
}

pub struct TrackedData {
    pub(crate) tracked: Vec<Box<dyn WrappedTrackable>>,
    pub(crate) filter_results: Vec<Option<usize>>,
}

impl TrackedData {
    pub fn new(pkt_results: Vec<Option<usize>>) -> Self {
        TrackedData {
            tracked: Vec::new(), // TODO
            filter_results: pkt_results,
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, session_id: Option<usize>) {
        for tracked in &mut self.tracked {
            tracked.pre_match_wrapped(pdu.clone(), session_id);
        }
    }

    fn on_match(&mut self, session: Session, subscription: &dyn WrappedSubscription) {
        for tracked in &mut self.tracked {
            tracked.on_match_wrapped(session.clone(), subscription);
        }
    }

    fn post_match(&mut self, pdu: L4Pdu, subscription: &dyn WrappedSubscription) {
        for tracked in &mut self.tracked {
            tracked.post_match_wrapped(pdu.clone(), subscription);
        }
    }

    fn on_terminate(&mut self, subscription: &dyn WrappedSubscription) {
        for tracked in &mut self.tracked {
            tracked.on_terminate_wrapped(subscription);
        }
    }
}
