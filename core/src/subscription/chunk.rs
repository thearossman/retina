use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

use std::collections::VecDeque;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PayloadChunk {
    pub five_tuple: FiveTuple,
    pub data: Vec<u8>,
}

impl PayloadChunk {
    fn new(five_tuple: FiveTuple) -> Self {
        Self {
            five_tuple,
            data: vec![]
        }
    }
}

const WINDOW_SIZE: usize = 1000;

impl Subscribable for PayloadChunk {
    type Tracked = TrackedPayloadChunk;

    fn level() -> Level {
        Level::Connection
    }

    fn parsers() -> Vec<ConnParser> {
        vec![]
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


#[doc(hidden)]
pub struct TrackedPayloadChunk {
    five_tuple: FiveTuple,
    chunks: VecDeque<PayloadChunk>,
}

impl TrackedPayloadChunk {
    fn push_data(&mut self, pdu: L4Pdu) {
        let offset = pdu.offset();
        let payload_len = pdu.length();
        if payload_len == 0 || payload_len < offset {
            return;
        }
        if self.chunks.is_empty() {
            self.chunks.push_back(PayloadChunk::new(self.five_tuple));
        }
        if self.chunks.back().unwrap().data.len() + payload_len > WINDOW_SIZE {
            self.chunks.push_back(PayloadChunk::new(self.five_tuple));
        }
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, payload_len) {
            self.chunks.back_mut().unwrap().data.extend(data);
        }
    }
}

impl Trackable for TrackedPayloadChunk {
    type Subscribed = PayloadChunk;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedPayloadChunk {
            five_tuple,
            chunks: VecDeque::new(),
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.push_data(pdu);
    }

    fn on_match(&mut self, _session: Session, subscription: &Subscription<Self::Subscribed>) {
        self.chunks.drain(..).for_each(|chunk| {
            subscription.invoke(chunk);
        });
    }

    fn post_match(&mut self, pdu: L4Pdu, subscription: &Subscription<Self::Subscribed>) {
        self.push_data(pdu);
        if let Some(chunk) = self.chunks.front() {
            if chunk.data.len() >= WINDOW_SIZE {
                subscription.invoke(self.chunks.pop_front().unwrap());
            }
        }
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        self.chunks.drain(..).for_each(|chunk| {
            subscription.invoke(chunk);
        });
    }
}
