use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session, SessionData};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

lazy_static! {
    static ref MAX_WINDOW: usize = 10;
    static ref THRESHOLD: usize = 1000;
}

pub struct Chunk {
    pub data: Vec<u8>,
}

impl Subscribable for Chunk {
    type Tracked = TrackedChunk;

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


// Define functions to consume &[u8]
// Note - can later do this as a vec of Box<dyn fn>
type ChunkFn = fn(&[u8]);

fn session_cb(data: &[u8]) {
}

fn data_cb(data: &[u8]) {
}

lazy_static! {
    static ref CHUNK_FNS: [ChunkFn; 2] = [session_cb, data_cb];
    static ref CONSUMERS: Vec<Consumer> = {
        let mut outp = vec![];
        outp.push(Consumer::new(50, 0));
        outp.push(Consumer::new(100, 0));
        //outp.push(Consumer::new(10, 1));
        outp
    };
}


#[doc(hidden)]
pub struct TrackedChunk {
    #[allow(unused)]
    five_tuple: FiveTuple,
    save_payload: bool,
    pub(crate) payload: Vec<u8>,
    save_packets: bool,
    pub(crate) packets: Vec<Mbuf>,
    consumers: Vec<Consumer>,
    // TODO max length? start dropping packets...
}

impl TrackedChunk {
    fn extend(&mut self, pdu: L4Pdu) {
        if !self.save_payload && !self.save_payload {
            return;
        }
        
        if self.save_payload {
            let length = pdu.length();
            let offset = pdu.offset();
            if let Ok(payload) = pdu.mbuf_ref().get_data_slice(offset, length) {
                self.payload.extend(payload);
            }
        }
        
        if self.save_packets {
            self.packets.push(pdu.mbuf_own());
        }
        
    }

    // TODO consumers need to be updated
    //      can't do this until all have matched (or not matched)
    /* 
    fn drain(&mut self) {
        if self.payload.len() > *MAX_WINDOW + *THRESHOLD {
            let idx = self.payload.len() - *MAX_WINDOW;
            let (_, keep) = self.payload.split_at_mut(idx);
            self.payload = Vec::from(keep);
        }
    }
     */
}

impl Trackable for TrackedChunk {
    type Subscribed = Chunk;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedChunk {
            five_tuple,
            save_payload: true,
            payload: Vec::new(),
            save_packets: true,
            packets: Vec::new(),
            consumers: CONSUMERS.clone(),
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.extend(pdu);
    }

    fn on_match(&mut self, session: Session, _subscription: &Subscription<Self::Subscribed>) {
        // tmp - disambiguate multiple subscriptions
        if let SessionData::Http(_) = session.data {
            self.consumers[0].consume(&self.payload);
        } else if let SessionData::Tls(_) = session.data {
            self.consumers[1].consume(&self.payload);
        }
    }

    fn post_match(&mut self, pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {
        self.extend(pdu);
        for c in &mut self.consumers {
            c.consume(&self.payload);
        }
    }

    // TODO need to ensure draining happens for not connection level...
    fn on_terminate(&mut self, _subscription: &Subscription<Self::Subscribed>) {
        for c in &mut self.consumers {
            c.drain(&self.payload);
        }
    }

    // Another send_payload function that's invoked after app headers are parsed...? 
    // Can be another action...

}

// Note - tried to do this with cb Fn stored directly, but then this would
// require not using the Vec<> in the TrackedChunk or would require Vec<Box<dyn
// to allow for different functions. 

#[derive(Debug, Clone)]
pub struct Consumer {
    window_size: usize,
    position: usize,
    pub(crate) matched: bool,
    cb_idx: usize,
}

impl Consumer {
    fn new(window_size: usize, cb_idx: usize) -> Self {
        Self {
            window_size,
            position: 0,
            matched: false,
            cb_idx,
        }
    }

    fn consume(&mut self, tracked: &Vec<u8>) {
        while self.matched && self.position + self.window_size < tracked.len() {
            let slice = &tracked[self.position..(self.position + self.window_size)];
            CHUNK_FNS[self.cb_idx](slice);
            self.position += self.window_size;
        }
    }

    fn drain(&mut self, tracked: &Vec<u8>) {
        self.consume(tracked);
        if self.matched && self.position < tracked.len() {
            let slice = &tracked[self.position..tracked.len()];
            CHUNK_FNS[self.cb_idx](slice);
            self.position = tracked.len();
        }
    }
}