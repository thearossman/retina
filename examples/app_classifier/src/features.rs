use retina_core::protocols::packet::tcp::{ACK, SYN};
use retina_core::subscription::Tracked;
use retina_core::{L4Pdu, StateTxData};
use retina_filtergen::*;
use std::time::Instant;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Features {
    pub proto: f64,
    pub s_port: f64,
    pub d_port: f64,
    pub s_load: f64,
    pub d_load: f64,
    pub syn_ack: f64,
    pub ack_dat: f64,
}

impl Features {
    pub fn feature_vec(&self) -> Vec<f64> {
        Vec::new() // TODO
    }

    pub fn from_tracked(tracked: &TrackedFeatures) -> Option<Self> {
        if tracked.ack_ts.is_none() || tracked.syn_ack_ts.is_none() || tracked.syn_ts.is_none() {
            return None;
        }
        let end = tracked.s_last_ts.unwrap().max(tracked.d_last_ts.unwrap());
        let duration = end.duration_since(tracked.syn_ts.unwrap()).as_secs_f64();
        Some(Features {
            proto: tracked.proto,
            s_port: tracked.s_port,
            d_port: tracked.d_port,
            s_load: tracked.s_bytes_sum * 8e9 / duration, // Gbps
            d_load: tracked.d_bytes_sum * 8e9 / duration,
            syn_ack: tracked
                .syn_ack_ts
                .unwrap()
                .duration_since(tracked.syn_ts.unwrap())
                .as_millis() as f64,
            ack_dat: tracked
                .ack_ts
                .unwrap()
                .duration_since(tracked.syn_ack_ts.unwrap())
                .as_millis() as f64,
        })
    }
}

// TODO - temp; should define more elegantly
#[datatype]
pub struct TrackedFeatures {
    pub cnt: u64,

    pub syn_ts: Option<Instant>,
    pub syn_ack_ts: Option<Instant>,
    pub ack_ts: Option<Instant>,

    pub s_last_ts: Option<Instant>,
    pub d_last_ts: Option<Instant>,

    pub s_pkt_cnt: f64,
    pub d_pkt_cnt: f64,

    pub proto: f64,
    pub s_port: f64,
    pub d_port: f64,

    pub s_bytes_sum: f64,
    pub d_bytes_sum: f64,
    pub s_bytes_min: f64,
    pub d_bytes_min: f64,
    pub s_bytes_max: f64,
    pub d_bytes_max: f64,
}

impl Tracked for TrackedFeatures {
    fn new(first_pkt: &L4Pdu) -> Self {
        TrackedFeatures {
            cnt: 0,

            syn_ts: None,
            syn_ack_ts: None,
            ack_ts: None,

            s_last_ts: None,
            d_last_ts: None,

            s_pkt_cnt: 0.0,
            d_pkt_cnt: 0.0,

            proto: first_pkt.ctxt.proto as f64,
            s_port: first_pkt.ctxt.src.port() as f64,
            d_port: first_pkt.ctxt.dst.port() as f64,

            s_bytes_sum: 0.0,
            d_bytes_sum: 0.0,
            s_bytes_min: f64::NAN,
            d_bytes_min: f64::NAN,
            s_bytes_max: f64::NAN,
            d_bytes_max: f64::NAN,
            // TODO add more features (e.g., IATs)
        }
    }

    #[datatype_group("TrackedFeatures,level=L4InPayload")]
    fn update(&mut self, segment: &L4Pdu) {
        self.cnt += 1;
        let curr_ts = segment.ts;
        // Src -> dst
        if segment.dir {
            if self.syn_ts.is_none() {
                self.syn_ts = Some(curr_ts.clone());
            }
            self.s_last_ts = Some(curr_ts.clone());
            self.s_pkt_cnt += 1.0;
            self.s_bytes_sum += segment.length() as f64;
            self.s_bytes_min = self.s_bytes_min.min(segment.length() as f64);
            self.s_bytes_max = self.s_bytes_max.max(segment.length() as f64);
            if !self.syn_ack_ts.is_none() && self.ack_ts.is_none() {
                if segment.flags() & ACK != 0 {
                    self.ack_ts = Some(curr_ts.clone());
                }
            }
        } else {
            self.d_last_ts = Some(curr_ts.clone());
            self.d_pkt_cnt += 1.0;
            self.d_bytes_sum += segment.length() as f64;
            self.d_bytes_min = self.d_bytes_min.min(segment.length() as f64);
            self.d_bytes_max = self.d_bytes_max.max(segment.length() as f64);
            if self.syn_ack_ts.is_none() {
                if segment.flags() & SYN != 0 && segment.flags() & ACK != 0 {
                    self.syn_ack_ts = Some(curr_ts.clone());
                }
            }
        }
    }

    fn clear(&mut self) {}

    fn phase_tx(&mut self, _tx: &StateTxData) {}
}

// Helper for training //
lazy_static::lazy_static! {
    static ref NFLX_REGEX: regex::Regex = regex::Regex::new(r"*.nflxvideo.net$").unwrap();
    static ref TWITCH_REGEX: regex::Regex = regex::Regex::new(
        r"(*.ttvnw.net$)|(*.hls.ttvnw.net)"
    ).unwrap();
    static ref ZOOM_REGEX: regex::Regex = regex::Regex::new(r"*.zoom.us$").unwrap();
    static ref TEAMS_REGEX: regex::Regex = regex::Regex::new(r"*.teams.microsoft.com$").unwrap();
    static ref FACEBOOK_REGEX: regex::Regex = regex::Regex::new(
        r"(*.facebook.com$)|(*.fbcdn.net$)"
    ).unwrap();
}

pub fn sni_to_label(sni: &str) -> String {
    if sni == "nflxvideo.net" {
        return "netflix".into();
    }
    if sni == "ttvnw.net" || sni == "hls.ttvnw.net" {
        return "twitch".into();
    }
    if sni == "zoom.us" {
        return "zoom".into();
    }
    if sni == "teams.microsoft.com" {
        return "microsoft_teams".into();
    }
    if sni == "facebook.com" || sni == "fbcdn.net" {
        return "facebook".into();
    }

    if NFLX_REGEX.is_match(sni) {
        return "netflix".into();
    }
    if TWITCH_REGEX.is_match(sni) {
        return "twitch".into();
    }
    if ZOOM_REGEX.is_match(sni) {
        return "zoom".into();
    }
    if TEAMS_REGEX.is_match(sni) {
        return "microsoft_teams".into();
    }
    if FACEBOOK_REGEX.is_match(sni) {
        return "facebook".into();
    }

    "Unknown".into()
}

#[cache_file("$RETINA_HOME/examples/app_classifier/data.txt")]
fn _cache_file() {}
