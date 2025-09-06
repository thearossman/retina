use retina_core::{L4Pdu, StateTxData, protocols::stream::SessionProto};
#[allow(unused_imports)]
use retina_filtergen::{cache_file, datatype, datatype_group};
use std::time::{Duration, Instant};
use welford::Welford;

const STARTUP_TS: u64 = 60; // Seconds to ignore at start of connection
const INTERVAL_TS: u64 = 10; // Interval before marking as ready and clearing

#[cfg_attr(
    not(feature = "skip_expand"),
    cache_file("$RETINA_HOME/examples/ml_qos/data.txt")
)]
fn _cache_file() {}

// Features from Fig 8
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct FeatureChunk {
    // All previous average segment size
    // In features: allprev_avg_chunksize
    pub all_prev_avg_seg_size: f64,
    // All previous max segment size
    // In features: allprev_max_chunksize
    pub all_prev_max_seg_size: f64,
    // All previous STD segment size
    // In features: allprev_std_chunksize
    pub all_prev_std_seg_size: f64,
    // Last 10 min segment size
    // In features: 10_min_chunksize
    pub last_10_min_seg_size: f64,
    // Cumsum segment size
    // In features: cumsum_chunksizes
    pub cumsum_seg_size: f64,
    // Last 10 std segment size TODO this may be last 10 *segments*
    // In features: 10_std_chunksize
    pub last_10_std_seg_size: f64,
    // Last 10 max segment size
    // In features: 10_max_chunksize
    pub last_10_max_seg_size: f64,
    // Last 10 avg segment size
    // In features: 10_avg_chunksize
    pub last_10_avg_seg_size: f64,
    // Last 10 EWMA segment size [TODO]
    // In features: 10_EWMA_chunksizes
    // pub last_10_ewma_seg_size: f64,

    // Median packet inter-arrival time downstream [TODO]
    // In features: down_chunk_iat_50 (??)
    // pub med_pkt_iat_down: f64,
    // Number of previous segment requests
    // TODO something in `user`?
    // pub n_prev_seg_reqs: f64,

    /* For calculating running stats */
    welford_seg_size_all: Welford<f64>,
    welford_seg_size_last_10: Welford<f64>,

    /* For managing intervals */
    last_interval_start: Instant,
    conn_start: Instant,
    pub ready: bool,

    /* Current segment */
    // Segment tracker
    segment_tracker: SegmentTracker,
}

impl FeatureChunk {
    pub fn new(pdu: &L4Pdu) -> Self {
        FeatureChunk {
            all_prev_avg_seg_size: 0.0,
            all_prev_max_seg_size: 0.0,
            all_prev_std_seg_size: 0.0,
            last_10_min_seg_size: 0.0,
            cumsum_seg_size: 0.0,
            last_10_std_seg_size: 0.0,
            last_10_max_seg_size: 0.0,
            last_10_avg_seg_size: 0.0,
            // last_10_ewma_seg_size: 0.0,
            // med_pkt_iat_down: 0.0,
            // n_prev_seg_reqs: 0.0,
            welford_seg_size_all: Welford::<f64>::new(),
            welford_seg_size_last_10: Welford::<f64>::new(),
            last_interval_start: pdu.ts,
            conn_start: pdu.ts,
            ready: false,
            segment_tracker: SegmentTracker::new(),
        }
    }

    pub fn reset(&mut self) {
        self.ready = false;
        // Reset all "last 10" features to 0
        self.last_10_min_seg_size = 0.0;
        self.last_10_std_seg_size = 0.0;
        self.last_10_max_seg_size = 0.0;
        // self.last_10_ewma_seg_size = 0.0;
        self.last_10_avg_seg_size = 0.0;
        // self.med_pkt_iat_down = 0.0;
        self.welford_seg_size_last_10 = Welford::<f64>::new();
    }

    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("FeatureChunk,level=L7OnDisc")
    )]
    pub fn protocol_id(&mut self, proto: &StateTxData) {
        if let StateTxData::L7OnDisc(prot) = proto {
            self.segment_tracker.set_protocol(prot.clone());
        }
    }

    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("FeatureChunk,level=L4InPayload")
    )]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        // Haven't started collecting data yet
        if pdu.ts.duration_since(self.conn_start) <= Duration::from_secs(STARTUP_TS) {
            return;
        }
        // New interval
        if self.ready {
            self.reset();
        }
        // Update existing segment
        if let Some(seg_size) = self.segment_tracker.new_segment(pdu) {
            // New video segment is done
            self.update_data(seg_size);
        }
        // After processing this packet, indicate to callback that new chunk of data is available
        if pdu.ts.duration_since(self.last_interval_start) >= Duration::from_secs(INTERVAL_TS) {
            self.ready = true;
            self.last_interval_start = pdu.ts;
        }
    }

    /// Process new video segment
    pub fn update_data(&mut self, seg_size: f64) {
        self.welford_seg_size_all.push(seg_size);
        self.welford_seg_size_last_10.push(seg_size);

        // Running counters (all)
        self.all_prev_avg_seg_size = self.welford_seg_size_all.mean().unwrap();
        self.all_prev_max_seg_size = max_cmp(self.all_prev_max_seg_size, seg_size);
        self.all_prev_std_seg_size = match self.welford_seg_size_all.var() {
            Some(v) => v.sqrt(),
            None => 0.0,
        };

        // Running counters (last 10s)
        self.last_10_min_seg_size = if self.last_10_min_seg_size > 0.0 {
            min_cmp(self.last_10_min_seg_size, seg_size) as f64
        } else {
            seg_size
        };
        self.cumsum_seg_size += seg_size;
        self.last_10_std_seg_size = match self.welford_seg_size_last_10.var() {
            Some(v) => v.sqrt(),
            None => 0.0,
        };
        self.last_10_max_seg_size = max_cmp(self.last_10_max_seg_size, seg_size);

        // TODO last_10_ewma_seg_size

        self.last_10_avg_seg_size = self.welford_seg_size_last_10.mean().unwrap();

        // Request counter
        // self.n_prev_seg_reqs += 1.0;

        // TODO med_pkt_iat_down
    }

    /// Returns a vector in the order of training data:
    /// - allprev_avg_chunksize,
    /// - allprev_max_chunksize,
    /// - allprev_std_chunksize,
    /// - 10_min_chunksize,
    /// - cumsum_chunksizes,
    /// - 10_std_chunksize,
    /// - 10_max_chunksize,
    /// - 10_avg_chunksize
    pub fn to_feature_vec(&self) -> Vec<f64> {
        Vec::from([
            self.all_prev_avg_seg_size,
            self.all_prev_max_seg_size,
            self.all_prev_std_seg_size,
            self.last_10_min_seg_size,
            self.cumsum_seg_size,
            self.last_10_std_seg_size,
            self.last_10_max_seg_size,
            self.last_10_avg_seg_size,
        ])
    }
}

fn min_cmp(a: f64, b: f64) -> f64 {
    if let Some(ordering) = a.partial_cmp(&b) {
        return match ordering {
            std::cmp::Ordering::Less => a,
            _ => b,
        };
    }
    panic!("{:?} or {:?} is NaN", a, b);
}

fn max_cmp(a: f64, b: f64) -> f64 {
    if min_cmp(a, b) == a { b } else { a }
}

pub const TLS_RECORD_HDR_SIZE: usize = 5;

/// Implements the segment tracking mechanism described in Bronzino et. al.
/// Note: these refer to "segments of video", not TCP segments.
pub struct SegmentTracker {
    /// Timestamp of the last-seen upstream packet with a non-zero payload.
    /// Note: for QUIC, this would be the last-seen upstream packet with a
    /// payload >150 bytes.
    pub last_seg_start: Option<Instant>,
    /// Count of the payload bytes seem in the subsequent downstream traffic,
    /// used to determine video segment sizes.
    pub curr_seg_size: usize,
    /// Identified app-layer protocol
    pub proto: SessionProto,
}

impl SegmentTracker {
    pub fn new() -> Self {
        SegmentTracker {
            last_seg_start: None,
            curr_seg_size: 0,
            proto: SessionProto::Null,
        }
    }

    pub fn header_size(&mut self, _pdu: &L4Pdu) -> usize {
        match self.proto {
            SessionProto::Tls => TLS_RECORD_HDR_SIZE,
            SessionProto::Quic => panic!("QUIC unimplemented"),
            _ => panic!("Unsupported protocol"),
        }
    }

    pub fn threshold(&mut self) -> usize {
        match self.proto {
            SessionProto::Tls => 0,
            SessionProto::Quic => panic!("QUIC unimplemented"),
            _ => panic!("Unsupported protocol"),
        }
    }

    pub fn set_protocol(&mut self, proto: SessionProto) {
        self.proto = proto;
    }

    pub fn new_segment(&mut self, pdu: &L4Pdu) -> Option<f64> {
        // Start of new segment
        self.last_seg_start = Some(pdu.ts);
        let seg_size = self.curr_seg_size as f64;
        self.curr_seg_size = 0;
        Some(seg_size)
    }

    pub fn update(&mut self, pdu: &L4Pdu) -> Option<f64> {
        match pdu.dir {
            true => {
                if pdu.length() > self.threshold() + self.header_size(pdu) {
                    return self.new_segment(pdu);
                }
            }
            false => {
                if self.last_seg_start.is_some() {
                    self.curr_seg_size += pdu.length() - self.header_size(pdu);
                }
            }
        }
        None
    }
}
