use crate::conntrack::conn_id::{FiveTuple, ConnId};
use crate::protocols::stream::{Session};
use crate::conntrack::pdu::{L4Pdu};
#[allow(unused_imports)]
use std::collections::HashMap;
#[allow(unused_imports)]
use std::time::{Duration, Instant};
#[allow(unused_imports)]
use crate::protocols::packet::tcp::{ACK, FIN, RST, SYN};

#[cfg(feature="user-def")]
include!(concat!(env!("OUT_DIR"), "/custom.rs"));


use serde::{Serialize, Deserialize};

#[derive(Debug)]
pub struct ConnectionData {
    #[cfg(connection="five_tuple")]
    pub five_tuple: FiveTuple,
    #[cfg(connection="timing")]
    pub timing: Timing,
    #[cfg(feature="user-def")]
    pub user_data: UserSubscribable,

    // TODOTR not implemented yet 
    /* 
    #[cfg(connection="history")]
    pub history: Vec<u8>,
    // TODO FLOW
    #[cfg(connection="orig_flow")]
    pub orig: FlowData,
    #[cfg(connection="resp_flow")]
    pub resp: FlowData,
    */
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Timing {
    #[cfg(timing="ts")]
    #[serde(skip_serializing, skip_deserializing)]
    pub ts: Option<Instant>,
    #[cfg(timing="duration")]
    pub duration: Duration,
    #[cfg(timing="max_inactivity")]
    pub max_inactivity: Duration,
    #[cfg(timing="time_to_second_packet")]
    pub time_to_second_packet: Duration,
}


#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct FlowData {
    #[cfg(flow="nb_pkts")]
    pub nb_pkts: u64,
    #[cfg(flow="nb_malformed_pkts")]
    pub nb_malformed_pkts: u64,
    #[cfg(flow="nb_late_start_pkts")]
    pub nb_late_start_pkts: u64,
    #[cfg(flow="nb_bytes")]
    pub nb_bytes: u64,
    #[cfg(flow="max_simult_gaps")]
    pub max_simult_gaps: u64,
    #[cfg(flow="data_start")]
    pub data_start: u32,
    #[cfg(flow="capacity")]
    pub capacity: usize,
    // chunk
    #[cfg(flow="gaps")]
    pub gaps: HashMap<u32, u64>,
}

#[allow(dead_code)]
struct TimingTracker {
    pub first_seen_ts: Instant,
    pub last_seen_ts: Instant,
    pub second_seen_ts: Option<Instant>,
    packets_seen: usize,
    pub duration: Duration,
    pub max_inactivity: Duration,
}

#[allow(dead_code)]
impl TimingTracker {
    pub fn new() -> Self {
        let now = Instant::now(); 
        TimingTracker {
            first_seen_ts: now,
            last_seen_ts: now,
            second_seen_ts: None,
            packets_seen: 0,
            duration: Duration::default(),
            max_inactivity: Duration::default(),
        }
    }

    pub fn update(&mut self) {
        let _now = Instant::now();
        self.packets_seen += 1;

        #[cfg(connection="duration")]
        {
            self.duration = _now - self.first_seen_ts;
        }

        #[cfg(connection="max_inactivity")]
        {
            let inactivity = now - self.last_seen_ts;
            if inactivity > self.max_inactivity {
                self.max_inactivity = inactivity;
            }
        }
        #[cfg(connection="time_to_second_packet")]
        {
            if self.packets_seen == 2 {
                self.second_seen_ts = Some(now);
            }
        }
    }

    pub fn to_data(self) -> Timing {

        let (mut _duration, mut _max_inactivity, mut _time_to_second_packet) = {(
            Duration::default(),
            Duration::default(),
            Duration::default(),
        )};

        if self.packets_seen > 1 {
            #[cfg(timing="duration")]
            {
                _duration = self.last_seen_ts - self.first_seen_ts;
            }
            #[cfg(timing="max_inactivity")]
            {
                _max_inactivity = self.max_inactivity;
            }
            #[cfg(timing="time_to_second_packet")]
            {
                _time_to_second_packet = self.second_seen_ts.unwrap() - self.first_seen_ts;
            }
        }

        Timing {
            #[cfg(timing="ts")]
            ts: self.first_seen_ts,
            #[cfg(timing="duration")]
            duration: _duration,
            #[cfg(timing="max_inactivity")]
            max_inactivity: _max_inactivity,
            #[cfg(timing="time_to_second_packet")]
            time_to_second_packet: _time_to_second_packet,
        }
    }
}

#[allow(dead_code)]
pub(super) struct ConnectionTracker {
    connections: HashMap<ConnId, (TimingTracker, FiveTuple, UserTracked)>,
    // TODOTR history, flowdata
}

#[allow(dead_code)]
impl ConnectionTracker {

    fn track(&mut self, pdu: &L4Pdu) {
        let five_tuple = FiveTuple::from_ctxt(pdu.ctxt);
        let conn_id = five_tuple.conn_id();
        let entry = self.connections
                       .entry(conn_id)
                       .or_insert((TimingTracker::new(), five_tuple, UserTracked::new()));

        #[cfg(connection="timing")]
        entry.0.update();

        #[cfg(feature="user-def")]
        entry.2.packet_received(pdu);
    }

    pub fn new(five_tuple: FiveTuple) -> Self {

        let mut con = ConnectionTracker {
            connections: HashMap::new(),
        }; 
        con.connections.insert(five_tuple.conn_id(), (TimingTracker::new(), five_tuple, UserTracked::new()));
        con
    }

    pub fn pre_match(&mut self, pdu: &L4Pdu, _session_id: Option<usize>) {
        self.track(pdu);
    }

    pub fn on_match(&mut self, _session: &Session)  { }

    pub fn post_match(&mut self, pdu: &L4Pdu) { 
        self.track(pdu);
    }

    pub fn on_terminate(&mut self) { }

    pub fn to_data(self) -> Vec<ConnectionData> {
        let mut ret = vec![];

        for (_, _v) in self.connections {
            ret.push(
                ConnectionData {
                    #[cfg(connection="five_tuple")]
                    five_tuple: _v.1, 
                    #[cfg(connection="timing")]
                    timing: _v.0.to_data(),
                    #[cfg(feature="user-def")]
                    user_data: _v.2.to_data()
                }
            );
        }

        ret
    }
}