use retina_core::filter::{DataType, Level, SubscriptionSpec};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use crate::datatypes::datatypes;

// Specify subscription specs from a file
#[derive(Serialize, Deserialize)]
pub(crate) struct ConfigRaw {
    pub(crate) subscriptions: Vec<SubscriptionRaw>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SubscriptionRaw {
    pub(crate) filter: String,
    #[serde_as(as = "serde_with::OneOrMany<_>")]
    pub(crate) datatypes: Vec<String>,
    pub(crate) callback: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SubscriptionConfig {
    pub(crate) subscriptions: Vec<SubscriptionSpec>,
}

impl SubscriptionConfig {
    pub(crate) fn from_raw(config: &ConfigRaw) -> Self {
        let mut subscriptions = vec![];
        for s in &config.subscriptions {
            assert!(!s.datatypes.is_empty());
            let mut spec = SubscriptionSpec::new(s.filter.clone(), s.callback.clone());
            for datatype_str in &s.datatypes {
                Self::validate_datatype(datatype_str.as_str());
                let datatype = datatypes().lock().unwrap().get(datatype_str.as_str()).unwrap().clone();
                spec.add_datatype(datatype);
            }
            spec.validate_spec();
            subscriptions.push(spec);
        }
        Self { subscriptions }
    }

    pub(crate) fn from_file(filepath_in: &str) -> Self {
        let config_str = std::fs::read_to_string(filepath_in)
            .unwrap_or_else(|err| panic!("ERROR: File read failed {}: {:?}", filepath_in, err));

        let config: ConfigRaw = toml::from_str(&config_str)
            .unwrap_or_else(|err| panic!("ERROR: Config file invalid {}: {:?}", filepath_in, err));
        Self::from_raw(&config)
    }

    fn validate_datatype(datatype: &str) {
        let datatypes = datatypes().lock().unwrap();
        if !datatypes.contains_key(datatype) {
            let valid_types: Vec<&String> = datatypes.keys().collect();
            panic!(
                "Invalid datatype: {};\nDid you mean:\n {:?}",
                datatype,
                valid_types // TODO format better
            );
        }
    }
}

////// TMP //////
lazy_static! {
    /// To add a datatype, add it to the DATATYPES map
    /// This is read by the filtergen crate to generate code
    pub static ref DATATYPES: HashMap<&'static str, DataType> = {
        HashMap::from([
            ("ConnRecord", DataType::new_default_connection("ConnRecord")),
            (
                "ConnDuration",
                DataType::new_default_connection("ConnDuration"),
            ),
            ("PktCount", DataType::new_default_connection("PktCount")),
            ("ByteCount", DataType::new_default_connection("ByteCount")),
            (
                "InterArrivals",
                DataType::new_default_connection("InterArrivals"),
            ),
            (
                "ConnHistory",
                DataType::new_default_connection("ConnHistory"),
            ),
            (
                "HttpTransaction",
                DataType::new_default_session(
                    "HttpTransaction",
                    vec!["http"]
                ),
            ),
            (
                "DnsTransaction",
                DataType::new_default_session("DnsTransaction", vec!["dns"]),
            ),
            (
                "TlsHandshake",
                DataType::new_default_session("TlsHandshake", vec!["tls"]),
            ),
            (
                "QuicStream",
                DataType::new_default_session("QuicStream", vec!["quic"]),
            ),
            ("ZcFrame", DataType::new_default_packet("ZcFrame")),
            ("Payload", DataType::new_default_packet("Payload")),
            ("SessionList", {
                DataType {
                    level: Level::Connection,
                    needs_parse: true,
                    track_sessions: true,
                    needs_update: false,
                    needs_reassembly: false,
                    needs_packet_track: false,
                    stream_protos: vec!["tls", "dns", "http", "quic"].iter().map(|s| s.to_string()).collect(),
                    as_str: "SessionList".to_string(),
                }
            }),
            ("BidirZcPktStream", { DataType::new_default_pktlist("BidirZcPktStream", false) }),
            ("OrigZcPktStream", { DataType::new_default_pktlist("OrigZcPktStream", false) }),
            ("RespZcPktStream", { DataType::new_default_pktlist("RespZcPktStream", false) }),
            ("OrigZcPktsReassembled", { DataType::new_default_pktlist("OrigZcPktsReassembled", true) }),
            ("RespZcPktsReassembled", { DataType::new_default_pktlist("RespZcPktsReassembled", true) }),
            ("BidirPktStream", { DataType::new_default_pktlist("BidirPktStream", false) }),
            ("OrigPktStream", { DataType::new_default_pktlist("OrigPktStream", false) }),
            ("RespPktStream", { DataType::new_default_pktlist("RespPktStream", false) }),
            ("OrigPktsReassembled", { DataType::new_default_pktlist("OrigPktsReassembled", true) }),
            ("RespPktsReassembled", { DataType::new_default_pktlist("RespPktsReassembled", true) }),
            ("CoreId", { DataType::new_default_static("CoreId") }),
            ("FiveTuple", { DataType::new_default_static("FiveTuple") }),
            ("EtherTCI", { DataType::new_default_static("EtherTCI") }),
            ("EthAddr", { DataType::new_default_static("EthAddr") }),
            ("FilterStr", { DataType::new_default_static("FilterStr") }),
        ])
    };
}

// Special cases: have specific conditions in generated code
// \Note ideally these would be implemented more cleanly
lazy_static! {
    /// To avoid copying, the `Tracked` structure in the framework --
    /// built at compile time -- will track certain generic, raw datatypes
    /// if a subset of subscriptions require them.
    ///
    /// For example: buffering packets may be required as a pre-match action for a
    /// packet-level datatype; it may also be required if one or more subscriptions request
    /// a connection-level `PacketList`. Rather than maintaining these lists separately --
    /// one for filtering and one for delivery -- the tracked packets are stored once.
    ///
    /// Core ID is a special case, as it cannot be derived from connection,
    /// session, or packet data. It is simpler to define it as a directly tracked datatype.
    ///
    /// The directly tracked datatypes are SessionList and CoreId
    pub static ref DIRECTLY_TRACKED: HashMap<&'static str, &'static str> = HashMap::from([
        ("SessionList", "sessions"),
        ("CoreId", "core_id")
    ]);

    /// See `FilterStr`
    #[doc(hidden)]
    pub static ref FILTER_STR: &'static str = "FilterStr";
}
