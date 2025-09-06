use retina_core::config::load_config;
use retina_core::protocols::stream::dns::Data;
use retina_core::protocols::{Session, stream::SessionData};
use retina_core::subscription::*;
use retina_core::{L4Pdu, Runtime};
use retina_datatypes::*;
use retina_filtergen::*;

use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;

//// Application-layer protocols ////

/// QUESTION - should these be grouped/streaming with datatypes...?
/// "Through a combination of network and User-Agent string signatures
/// we detect 41 applications..."

#[callback("http and DropHighVolume and DropInternal")]
fn get_http(http: &HttpTransaction, five_tuple: &AnonFiveTuple, ts: &StartTime) {
    // Browser information: K/V store from anonymized source IP to UA, with ts
    let user_agent = http.user_agent();
    // Dest information: K/V store from anon src IP to destination, with ts
    let dst = http.host();
    let uri = http.uri();
}

#[callback("(quic or tls) and DropHighVolume and DropInternal")]
fn get_tls(session: &Session, five_tuple: &AnonFiveTuple, ts: &StartTime) {
    let sni = match &session.data {
        SessionData::Tls(tls) => tls.sni(),
        SessionData::Quic(quic) => quic.tls.sni(),
        _ => unreachable!(),
    };
}

#[callback("dns and DropHighVolume and DropInternal")]
fn get_dns(dns: &DnsTransaction, five_tuple: &AnonFiveTuple, ts: &StartTime) {
    if dns.query.is_none()
        || dns.response.is_none()
        || dns.response.as_ref().unwrap().answers.is_empty()
    {
        return;
    }
    let data = &dns.response.as_ref().unwrap().answers;

    let mut resp_ips = vec![];
    for answer in data {
        resp_ips.push(match answer.data {
            Data::A(record) => IpAddr::V4(record.0),
            Data::Aaaa(record) => IpAddr::V6(record.0),
            _ => continue,
        });
    }
    if resp_ips.is_empty() {
        return;
    }

    let queries = dns.query_domain();
    let nameservers = dns.nameservers();
    // TODO just build up the cache...?
}

/// General information ///

#[callback("tcp or udp,level=L4FirstPacket")]
fn record_device(five_tuple: &AnonFiveTuple) {
    // TODO record the presence of an IP on the network
}

#[callback("(http or tls or quic) and DropHighVolume and DropInternal,level=L4Terminated")]
fn record_conn(
    pkts: &PktCount,
    bytes: &ByteCount,
    dur: &ConnDuration,
    hist: &ConnHistory,
    ft: &AnonFiveTuple,
    ts: &StartTime,
) {
}

/// Data for fingerprints ///

//// Filter out traffic we know will be irrelevant ////
/// [TODO might be more efficient to not group these]

#[filter]
#[derive(Debug)]
struct DropInternal;

impl StreamingFilter for DropInternal {
    fn new(_: &L4Pdu) -> Self {
        Self
    }

    fn clear(&mut self) {}
}

impl DropInternal {
    #[filter_group("DropInternal,level=L4FirstPacket")]
    fn on_first_pkt(&mut self, ft: &AnonFiveTuple) -> FilterResult {
        // TODO check dst against subnets
        FilterResult::Continue
    }

    #[filter_group("DropInternal,level=L7OnDisc")]
    fn on_session(&mut self, session: &Session) -> FilterResult {
        // TODO match on list of known HTTPs/SNIs
        FilterResult::Continue
    }
}

/// TODO this is where we'd use FilterResult::DropInHW
#[filter]
#[derive(Debug)]
struct DropHighVolume;

impl StreamingFilter for DropHighVolume {
    fn new(_: &L4Pdu) -> Self {
        Self
    }
    fn clear(&mut self) {}
}

impl DropHighVolume {
    #[filter_group("DropHighVolume,level=L4FirstPacket")]
    fn on_first_pkt(&mut self, ft: &AnonFiveTuple) -> FilterResult {
        // TODO check against known subnets
        FilterResult::Continue
    }

    #[filter_group("DropHighVolume,level=L7EndHdrs")]
    fn on_session(&mut self, session: &Session) -> FilterResult {
        // TODO match on list of known SNIs
        FilterResult::Accept
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
    // TODO outfile
}

#[input_files("$RETINA_HOME/datatypes/data.txt")]
#[retina_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
