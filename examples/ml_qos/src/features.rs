use retina_core::{L4Pdu, protocols::stream::SessionProto};
use std::time::Instant;
use welford::Welford;

// Features from Fig 8
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

    /* Current segment */
    // Segment tracker
    segment_tracker: SegmentTracker,
}

impl FeatureChunk {
    pub fn new(_pdu: &L4Pdu) -> Self {
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
            segment_tracker: SegmentTracker::new(),
        }
    }

    pub fn reset(&mut self) {
        // Reset all "last 10" features to 0
        self.last_10_min_seg_size = 0.0;
        self.last_10_std_seg_size = 0.0;
        self.last_10_max_seg_size = 0.0;
        // self.last_10_ewma_seg_size = 0.0;
        self.last_10_avg_seg_size = 0.0;
        // self.med_pkt_iat_down = 0.0;
        self.welford_seg_size_last_10 = Welford::<f64>::new();
    }

    pub fn protocol_id(&mut self, proto: &SessionProto) {
        self.segment_tracker.set_protocol(proto.clone());
    }

    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        if let Some(seg_size) = self.segment_tracker.new_segment(pdu) {
            self.update_data(seg_size);
        }
    }

    pub fn update_data(&mut self, seg_size: f64) {
        self.welford_seg_size_all.push(seg_size);
        self.welford_seg_size_last_10.push(seg_size);

        // Running counters (all)
        self.all_prev_avg_seg_size = self.welford_seg_size_all.mean().unwrap();
        self.all_prev_max_seg_size = max_cmp(self.all_prev_max_seg_size, seg_size);
        self.all_prev_std_seg_size = self.welford_seg_size_all.var().unwrap().sqrt();

        // Running counters (last 10s)
        self.last_10_min_seg_size = if self.last_10_min_seg_size > 0.0 {
            min_cmp(self.last_10_min_seg_size, seg_size) as f64
        } else {
            seg_size
        };
        self.cumsum_seg_size += seg_size;
        self.last_10_std_seg_size = self.welford_seg_size_last_10.var().unwrap().sqrt();
        self.last_10_max_seg_size = max_cmp(self.last_10_max_seg_size, seg_size);

        // TODO last_10_ewma_seg_size

        self.last_10_avg_seg_size = self.welford_seg_size_last_10.mean().unwrap();

        // Request counter
        // self.n_prev_seg_reqs += 1.0;

        // TODO med_pkt_iat_down
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

// ALL features in original dataset
// pub struct Features {
//     pub ten_EWMA_chunksizes: f64, // last_10_ewma_seg_size
//     pub ten_avg_chunksize: f64, // last_10_avg_seg_size
//     pub ten_chunksizes_50: f64,
//     //  10_chunksizes_50R
//     pub ten_chunksizes_75: f64,
//     //  10_chunksizes_75R,
//     pub ten_chunksizes_85: f64,
//     //  10_chunksizes_85R: f64,
//     pub ten_chunksizes_90: f64,
//     //  10_chunksizes_90R: f64,
//     pub ten_max_chunksize: f64,
//     pub ten_min_chunksize: f64,
//     pub ten_std_chunksize: f64,
//     //  absolute_timestamp: f64,
//     pub access_50_perc: f64,
//     pub access_75_perc: f64,
//     pub access_avg: f64,
//     pub access_max: f64,
//     pub access_min: f64,
//     pub access_var().unwrap().sqrt(): f64,
//     pub access_var: f64,
//     //  ads: f64,
//     //  all_prev_down_chunk_iat_50: f64,
//     //  all_prev_down_chunk_iat_50R: f64,
//     //  all_prev_down_chunk_iat_75: f64,
//     //  all_prev_down_chunk_iat_75R: f64,
//     //  all_prev_down_chunk_iat_85: f64,
//     //  all_prev_down_chunk_iat_85R: f64,
//     //  all_prev_down_chunk_iat_90: f64,
//     //  all_prev_down_chunk_iat_90R: f64,
//     //  all_prev_down_chunk_iat_avg: f64,
//     //  all_prev_down_chunk_iat_max: f64,
//     //  all_prev_down_chunk_iat_min: f64,
//     //  all_prev_down_chunk_iat_std: f64,
//     //  all_prev_up_chunk_iat_50: f64,
//     //  all_prev_up_chunk_iat_50R: f64,
//     //  all_prev_up_chunk_iat_75: f64,
//     //  all_prev_up_chunk_iat_75R: f64,
//     //  all_prev_up_chunk_iat_85: f64,
//     //  all_prev_up_chunk_iat_85R: f64,
//     //  all_prev_up_chunk_iat_90: f64,
//     //  all_prev_up_chunk_iat_90R: f64,
//     //  all_prev_up_chunk_iat_avg: f64,
//     //  all_prev_up_chunk_iat_max: f64,
//     //  all_prev_up_chunk_iat_min: f64,
//     //  all_prev_up_chunk_iat_std: f64,
//     //  allprev_avg_chunksize: f64,
//     //  allprev_chunksizes_50: f64,
//     //  allprev_chunksizes_50R: f64,
//     //  allprev_chunksizes_75: f64,
//     //  allprev_chunksizes_75R: f64,
//     //  allprev_chunksizes_85: f64,
//     //  allprev_chunksizes_85R: f64,
//     //  allprev_chunksizes_90: f64,
//     //  allprev_chunksizes_90R: f64,
//     //  allprev_max_chunksize: f64,
//     //  allprev_min_chunksize: f64,
//     //  allprev_std_chunksize: f64,
//     //  avg_flow_age: f64,
//     pub bitrate: f64,
//     pub bitrate_change: f64,
//     //  c_bitrate_switches: f64,
//     //  c_rebufferings: f64,
//     //  c_resolution_switches: f64,
//     //  chunk_end_time: f64,
//     //  chunk_start_time: f64,
//     pub cumsum_chunksizes: f64,
//     pub cumsum_diff: f64,
//     pub curr_chunksize: f64,
//     pub current_chunk_iat: f64,
//     //  deployment_session_id: f64,
//     pub down_chunk_iat_50: f64,
//     //  down_chunk_iat_50R: f64,
//     pub down_chunk_iat_75: f64,
//     //  down_chunk_iat_75R: f64,
//     pub down_chunk_iat_85: f64,
//     //  down_chunk_iat_85R: f64,
//     pub down_chunk_iat_90: f64,
//     //  down_chunk_iat_90R: f64,
//     pub down_chunk_iat_avg: f64,
//     pub down_chunk_iat_max: f64,
//     pub down_chunk_iat_min: f64,
//     pub down_chunk_iat_std: f64,
//     //  home_id: f64,
//     //  index: f64,
//     pub is_tcp: f64, // bool
//     //  n_bitrate_switches: f64,
//     //  n_chunks_down: f64,
//     //  n_chunks_up: f64,
//     //  n_prev_down_chunk: f64,
//     //  n_prev_up_chunk: f64,
//     //  n_rebufferings: f64,
//     //  parallel_flows: f64,
//     //  previous_bitrate: f64,
//     //  quality: f64,
//     //  relative_timestamp: f64,
//     //  resolution: f64,
//     //  service_Video_throughput_down: f64,
//     //  service_Video_throughput_up: f64,
//     //  service_non_video_throughput_down: f64,
//     //  service_non_video_throughput_up: f64,
//     //  session_id: f64,
//     //  size_diff_previous: f64,
//     pub startup_time: f64,
//     //  total_throughput_down: f64,
//     //  total_throughput_up: f64,
//     //  up_chunk_iat_50: f64,
//     //  up_chunk_iat_50R: f64,
//     //  up_chunk_iat_75: f64,
//     //  up_chunk_iat_75R: f64,
//     //  up_chunk_iat_85: f64,
//     //  up_chunk_iat_85R: f64,
//     //  up_chunk_iat_90: f64,
//     //  up_chunk_iat_90R: f64,
//     //  up_chunk_iat_avg: f64,
//     //  up_chunk_iat_max: f64,
//     //  up_chunk_iat_min: f64,
//     //  up_chunk_iat_std: f64,
//     //  up_down_ratio: f64,
//     //  video_duration: f64,
//     //  video_id: f64,
//     //  video_position: f64,
//     //  wireless_50_perc: f64,
//     //  wireless_75_perc: f64,
//     //  wireless_avg: f64,
//     //  wireless_max: f64,
//     //  wireless_min: f64,
//     //  wireless_var().unwrap().sqrt(): f64,
//     //  wireless_var: f64,
//     pub serverAckFlags: f64,
//     pub serverAvgBytesInFlight: f64,
//     pub serverAvgBytesPerPacket: f64,
//     pub serverAvgInterArrivalTime: f64,
//     pub serverAvgRetransmit: f64,
//     pub serverAvgRwnd: f64,
//     pub serverBitrateChange: f64,
//     //  serverByteCount: f64,
//     //  serverEndBytesPerPacket: f64,
//     //  serverFinFlags: f64,
//     pub serverGoodput: f64,
//     //  serverIdleTime: f64,
//     //  serverKurBytesInFlight: f64,
//     //  serverKurBytesPerPacket: f64,
//     //  serverKurInterArrivalTime: f64,
//     //  serverKurRetransmit: f64,
//     //  serverKurRwnd: f64,
//     pub serverMaxBytesInFlight: f64,
//     pub serverMaxBytesPerPacket: f64,
//     pub serverMaxInterArrivalTime: f64,
//     pub serverMaxRetransmit: f64,
//     pub serverMaxRwnd: f64,
//     pub serverMedBytesInFlight: f64,
//     pub serverMedBytesPerPacket: f64,
//     pub serverMedInterArrivalTime: f64,
//     pub serverMedRetransmit: f64,
//     //  serverMedRwnd: f64,
//     pub serverMinBytesInFlight: f64,
//     pub serverMinBytesPerPacket: f64,
//     pub serverMinInterArrivalTime: f64,
//     pub serverMinRetransmit: f64,
//     //  serverMinRwnd: f64,
//     pub serverOneRetransmit: f64,
//     pub serverOutOfOrderBytes: f64,
//     pub serverOutOfOrderPackets: f64,
//     pub serverPacketCount: f64,
//     pub serverPshFlags: f64,
//     pub serverRstFlags: f64,
//     //  serverSkeBytesInFlight: f64,
//     //  serverSkeBytesPerPacket: f64,
//     //  serverSkeInterArrivalTime: f64,
//     //  serverSkeRetransmit: f64,
//     //  serverSkeRwnd: f64,
//     pub serverStdBytesInFlight: f64,
//     pub serverStdBytesPerPacket: f64,
//     pub serverStdInterArrivalTime: f64,
//     pub serverStdRetransmit: f64,
//     pub serverStdRwnd: f64,
//     //  serverStrBytesPerPacket: f64,
//     pub serverSynFlags: f64,
//     pub serverThroughput: f64,
//     //  serverTwoRetransmit: f64,
//     pub serverUrgFlags: f64,
//     //  serverXRetransmit: f64,
//     //  serverZeroRetransmit: f64,
//     pub userAckFlags: f64,
//     pub userAvgBytesInFlight: f64,
//     pub userAvgBytesPerPacket: f64,
//     pub userAvgInterArrivalTime: f64,
//     pub userAvgRTT: f64,
//     pub userAvgRetransmit: f64,
//     //  userAvgRwnd: f64,
//     pub userByteCount: f64,
//     pub userEndBytesInFlight: f64,
//     pub userFinFlags: f64,
//     pub userGoodput: f64,
//     //  userIdleTime: f64,
//     //  userKurBytesInFlight: f64,
//     //  userKurBytesPerPacket: f64,
//     //  userKurInterArrivalTime: f64,
//     //  userKurRTT: f64,
//     //  userKurRetransmit: f64,
//     //  userKurRwnd: f64,
//     pub userMaxBytesInFlight: f64,
//     pub userMaxBytesPerPacket: f64,
//     pub userMaxInterArrivalTime: f64,
//     pub userMaxRTT: f64,
//     pub userMaxRetransmit: f64,
//     pub userMaxRwnd: f64,
//     pub userMedBytesInFlight: f64,
//     pub userMedBytesPerPacket: f64,
//     pub userMedInterArrivalTime: f64,
//     pub userMedRTT: f64,
//     pub userMedRetransmit: f64,
//     pub userMedRwnd: f64,
//     pub userMinBytesInFlight: f64,
//     pub userMinBytesPerPacket: f64,
//     pub userMinInterArrivalTime: f64,
//     pub userMinRTT: f64,
//     //  userMinRetransmit: f64,
//     //  userMinRwnd: f64,
//     pub userOneRetransmit: f64,
//     pub userOutOfOrderBytes: f64,
//     pub userOutOfOrderPackets: f64,
//     pub userPacketCount: f64,
//     pub userPshFlags: f64,
//     pub userRstFlags: f64,
//     //  userSkeBytesInFlight: f64,
//     //  userSkeBytesPerPacket: f64,
//     //  userSkeInterArrivalTime: f64,
//     //  userSkeRTT: f64,
//     //  userSkeRetransmit: f64,
//     //  userSkeRwnd: f64,
//     //  userStdBytesInFlight: f64,
//     pub userStdBytesPerPacket: f64,
//     pub userStdInterArrivalTime: f64,
//     pub userStdRTT: f64,
//     //  userStdRetransmit: f64,
//     //  userStdRwnd: f64,
//     pub userStrBytesInFlight: f64,
//     pub userSynFlags: f64,
//     pub userThroughput: f64,
//     pub userTwoRetransmit: f64,
//     pub userUrgFlags: f64,
//     pub userXRetransmit: f64,
//     //  userZeroRetransmit: f64,
//     //  service: f64,
//     pub startup3_3: f64, // bool
//     pub startup6_6: f64, // bool
//     pub startup5: f64, // bool
//     pub startup10: f64, // bool
//     //  startup_mc'
// }
