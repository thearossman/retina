use crate::L4Pdu;
use std::time::{Duration, Instant};

pub trait CallbackTimer {
    fn new(count: u64) -> Self;
    fn update(&mut self, pdu: &L4Pdu) -> bool;
}

pub struct Milliseconds {
    last_invoked: Instant,
    interval: Duration,
}

impl CallbackTimer for Milliseconds {
    fn new(count: u64) -> Self {
        Self {
            last_invoked: Instant::now(),
            interval: Duration::from_millis(count),
        }
    }

    fn update(&mut self, _pdu: &L4Pdu) -> bool {
        if Instant::now() - self.last_invoked >= self.interval {
            self.last_invoked = Instant::now();
            return true;
        }
        false
    }
}

pub struct Packets {
    count_remaining: u64,
    count: u64,
}

impl CallbackTimer for Packets {
    fn new(count: u64) -> Self {
        Self {
            count_remaining: count,
            count,
        }
    }

    fn update(&mut self, _pdu: &L4Pdu) -> bool {
        self.count_remaining -= 1;
        if self.count_remaining == 0 {
            self.count_remaining = self.count;
            return true;
        }
        false
    }
}

// Bytes, excluding Ethernet, IP, and TCP headers.
pub struct Bytes {
    count_remaining: u64,
    count: u64,
}

impl CallbackTimer for Bytes {
    fn new(count: u64) -> Self {
        Self {
            count_remaining: count,
            count,
        }
    }

    fn update(&mut self, pdu: &L4Pdu) -> bool {
        let len = pdu.length() as u64;
        if len >= self.count_remaining {
            let over = len - self.count_remaining;
            self.count_remaining = if over >= self.count {
                0
            } else {
                self.count - over
            };
            return true;
        }
        self.count_remaining -= len;
        false
    }
}
