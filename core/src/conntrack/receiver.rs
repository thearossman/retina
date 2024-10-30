use std::collections::BinaryHeap;
use std::cmp::Reverse; // Used to reverse the order for a min-heap
use std::time::{Instant, Duration};
use std::any::Any;
use super::conn::Conn;
use super::conn_id::ConnId;
use crate::lcore::CoreId;
use crate::subscription::Trackable;
use crossbeam_channel::{Receiver, tick};

use hashlink::linked_hash_map::{LinkedHashMap, RawEntryMut};

/// Wraps a subscription callback
pub type CallbackWrapper<T> = dyn FnMut(&T, &mut dyn Any, &CoreId) -> bool;

/// Timer for a single periodically-invoked callback
pub struct CallbackTimer<T>
where
    T: Trackable
{
    /// Callback to invoke
    pub(crate) callback: Box<CallbackWrapper<T>>,
    /// Scratch space required for the callback
    /// For example, some callbacks may wish to track the last
    /// packet index they received
    pub(crate) scratch: Box<dyn Any>,
    /// Connection ID to which this timer is associated
    pub(crate) conn_id: ConnId,
    /// Time interval at which the callback should be invoked
    pub(crate) period: Duration,
    /// Next invocation time; used to sort in binary heap
    pub(crate) invoke_at: Instant,
}

impl<T> CallbackTimer<T>
where
    T: Trackable
{
    pub fn new<F>(period: Duration, callback: Box<F>,
                  scratch: Box<dyn Any>,
                  conn_id: ConnId) -> Self
    where
        F: FnMut(&T, &mut dyn Any, &CoreId) -> bool + 'static,
    {
        CallbackTimer {
            callback,
            scratch,
            conn_id,
            period,
            invoke_at: Instant::now() + period,
        }
    }

    pub(super) fn reset(&mut self) {
        self.invoke_at = Instant::now() + self.period;
    }
}

impl<T> Ord for CallbackTimer<T>
where
    T: Trackable
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.invoke_at.cmp(&other.invoke_at)
    }
}

impl<T> PartialOrd for CallbackTimer<T>
where
    T: Trackable
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> PartialEq for CallbackTimer<T>
where
    T: Trackable
{
    fn eq(&self, other: &Self) -> bool {
        other.invoke_at == other.invoke_at
    }
}

impl<T> Eq for CallbackTimer<T> where T: Trackable {}

/// Tracks all callback timers for a connection table
/// and invokes callbacks periodically
pub(crate) struct CallbackTimerWheel<T>
where
    T: Trackable
{
    /// Fires every period ms
    ticker: Receiver<Instant>,
    /// Active timers, ordered by next invocation time
    /// Matched connections that have not terminated
    timers: Vec<BinaryHeap<Reverse<CallbackTimer<T>>>>,
    /// Start time of the timer wheel
    start_ts: Instant,
    /// Duration for each "bucket"
    bucket_duration: usize,
    /// Next bucket to check for callbacks
    next_bucket: usize,
}

impl<T> CallbackTimerWheel<T>
where
    T: Trackable
{
    pub(crate) fn new(timeout_resolution: usize, max_timeout_ms: usize) -> Self {
        let ticker = tick(Duration::from_millis(timeout_resolution as u64));
        let bucket_duration = timeout_resolution;
        let n_buckets = usize::div_ceil(max_timeout_ms, bucket_duration);
        CallbackTimerWheel {
            ticker,
            timers: (0..n_buckets).map(|_| BinaryHeap::new()).collect(),
            start_ts: Instant::now(),
            bucket_duration,
            next_bucket: 0,
        }
    }

    /// Insert a matched connection ID into the timerwheel
    pub(super) fn insert(&mut self, timer: CallbackTimer<T>)
    where
        T: Trackable
    {
        let bucket = self.bucket(&timer.invoke_at);
        self.timers[bucket].push(
            Reverse(timer)
        );
    }

    fn bucket(&self, time: &Instant) -> usize {
        // Bucket based on (invocation time - start time)
        let time_since_start = time.duration_since(self.start_ts).as_millis();
        // ...rounded down to closest bucket
        let nearest_period = time_since_start as usize / self.bucket_duration;
        // ...sized to fit the table
        nearest_period % self.timers.len()
    }

    /// Checks for and invokes callbacks
    pub(super) fn try_invoke(
        &mut self,
        table: &mut LinkedHashMap<ConnId, Conn<T>>,
        core_id: &CoreId,
    ) where
        T: Trackable
    {
        if let Ok(now) = self.ticker.try_recv() {
            let bucket_end = self.bucket(&Instant::now());
            for bucket in self.next_bucket..bucket_end {
                while let Some(timer) = self.timers[bucket].peek() {
                    if timer.0.invoke_at > now {
                        self.next_bucket = bucket;
                        return; // STOP all iterations
                    }
                    let mut timer = self.timers[bucket].pop().unwrap().0;
                    let conn_id = &timer.conn_id;
                    if let RawEntryMut::Occupied(mut occupied) = table.raw_entry_mut().from_key(conn_id) {
                        let conn = occupied.get_mut();
                        if conn.drop_pdu() { continue; }
                        if (timer.callback)(&conn.info.sdata, &mut timer.scratch, core_id) {
                            timer.reset();
                            self.insert(timer);
                        }
                    }
                }
            }
        }
    }
}