use retina_core::config::load_config;
use retina_core::{CoreId, Runtime};
use retina_datatypes::ZcFrame;

use std::sync::atomic::{Ordering, AtomicPtr};

use array_init::array_init;
use clap::Parser;
use std::path::PathBuf;
use std::io::{BufWriter, BufReader, Write};
use pcap_file::{PcapReader, PcapWriter};
use std::fs::File;

use rand::Rng;

use lazy_static::lazy_static;

use pnet::packet::{MutablePacket, ethernet::MutableEthernetPacket, ipv4::MutableIpv4Packet};
use pnet::packet::Packet as PnetPacket;
use pnet::util::MacAddr;

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for RESULTS
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;
// Temporary per-core files
const OUTFILE_PREFIX: &str = "websites_";

lazy_static! {
    static ref RESULTS: [AtomicPtr<Option<PcapWriter<BufWriter<File>>>>; ARR_LEN] = {
        let mut results = vec![];
        for core_id in 0..ARR_LEN {
            let file_name = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
            let buf_wtr = BufWriter::new(File::create(&file_name).unwrap());
            let pcap_wtr = Some(PcapWriter::new(buf_wtr).unwrap());
            let core_wtr = Box::into_raw(Box::new(pcap_wtr));
            results.push(core_wtr);
        }
        array_init(|i| AtomicPtr::new(results[i].clone()))
    };
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "pcap_dump.pcap"
    )]
    outfile: PathBuf,
}

lazy_static! {
    static ref CONST_SRC_MAC: MacAddr = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1);
    static ref CONST_DST_MAC: MacAddr = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf2);
    static ref KEY: [u8; 16] = {
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key);
        key
    };
}

fn callback(mut zcframe: ZcFrame, core_id: CoreId) {
    let data = zcframe.data_mut();
    let len = data.len();
    if let Some(mut eth) = MutableEthernetPacket::new(&mut data[..]) {
        let payload = MutableEthernetPacket::payload_mut(&mut eth);
        if let Some(mut ipv4) = MutableIpv4Packet::new(payload) {
            let src_anon = ipcrypt::encrypt(MutableIpv4Packet::get_source(&ipv4), &KEY);
            let dst_anon = ipcrypt::encrypt(MutableIpv4Packet::get_destination(&ipv4), &KEY);

            // Anonymize IPs
            MutableIpv4Packet::set_source(&mut ipv4, src_anon);
            MutableIpv4Packet::set_destination(&mut ipv4, dst_anon);

            // Clear out MAC addresses
            MutableEthernetPacket::set_source(&mut eth, *CONST_SRC_MAC);
            MutableEthernetPacket::set_destination(&mut eth, *CONST_DST_MAC);

            // Get packet
            let packet = eth.packet();

            // Write
            let ptr = RESULTS[core_id.raw() as usize].load(Ordering::Relaxed);
            let wtr = unsafe { &mut *ptr }.as_mut().unwrap();
            wtr.write(1, 0, packet, len as u32).unwrap();
        }
    }
}

fn process_results(outfile: &PathBuf) {

    let buf_writer = BufWriter::new(File::create(outfile).unwrap());
    let mut pcap_writer = PcapWriter::new(buf_writer).unwrap();

    let mut err_count = 0;
    let mut success_count = 0;

    // Combine core files
    // \Note doing this packet-by-packet is messy, but eliminates the need for
    //       manually updated pcap file metadata
    for core_id in 0..ARR_LEN {
        // Flush writer
        let ptr = RESULTS[core_id].load(Ordering::Relaxed);
        let ptr = unsafe { &mut *ptr };
        let wtr = std::mem::take(ptr).unwrap();
        wtr.into_writer().flush().unwrap();

        // Read core file
        let fp = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
        let core_file = File::open(fp.clone()).unwrap();
        let reader = BufReader::new(core_file);
        let pcap_reader = PcapReader::new(reader).unwrap();

        // Copy into shared file
        for pkt in pcap_reader {
            if let Ok(pkt) = pkt {
                if pcap_writer.write_packet(&pkt).is_err() {
                    err_count += 1;
                } else {
                    success_count += 1;
                }
            } else {
                err_count += 1;
            }
        }

        // Clear tmp file
        std::fs::remove_file(fp).unwrap();
    }
    println!("Wrote {} packets successfully, {} errors", success_count, err_count);
    let mut buf_wtr = pcap_writer.into_writer();
    buf_wtr.flush().unwrap();
}

fn validate_cores(num_cores: usize, exp_cores: usize, cores: Vec<CoreId>) {
    if num_cores > exp_cores {
        panic!(
            "Compile-time NUM_CORES ({}) must be <= num cores ({}) in config file",
            exp_cores, num_cores
        );
    }
    if cores.len() > 1 && !cores.windows(2).all(|w| w[1].raw() - w[0].raw() == 1) {
        panic!("Cores in config file should be consecutive for zero-lock indexing");
    }
    if cores[0].raw() > 1 {
        panic!("RX core IDs should start at 0 or 1");
    }
}

fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let cores = config.get_all_rx_core_ids();
    validate_cores(cores.len(), NUM_CORES, cores);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    process_results(&args.outfile);
}


use retina_core::filter::actions::*;
use retina_core::subscription::{Trackable, Subscribable};
pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}
pub struct TrackedWrapper {
    sessions: Vec<retina_core::protocols::Session>,
    mbufs: Vec<retina_core::Mbuf>,
    core_id: retina_core::CoreId,
}

impl TrackedWrapper {
    pub fn packets_owned(&mut self) -> &mut Vec<retina_core::Mbuf> {
        &mut self.mbufs
    }
}

impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(_pdu: &retina_core::L4Pdu, core_id: retina_core::CoreId) -> Self {
        Self {
            sessions: Vec::new(),
            mbufs: Vec::new(),
            core_id,
        }
    }

    fn update(&mut self, _pdu: &retina_core::L4Pdu, _reassembled: bool) {}

    fn core_id(&self) -> &retina_core::CoreId {
        &self.core_id
    }

    fn track_packet(&mut self, mbuf: retina_core::Mbuf) {
        self.mbufs.push(mbuf);
    }

    fn packets(&self) -> &Vec<retina_core::Mbuf> {
        &self.mbufs
    }

    fn drain_packets(&mut self) {
        self.mbufs = Vec::new();
    }

    fn clear(&mut self) {
        self.drain_packets();
        self.sessions = Vec::new();
    }

    fn sessions(&self) -> &Vec<retina_core::protocols::Session> {
        &self.sessions
    }

    fn track_session(&mut self, session: retina_core::protocols::Session) {
        self.sessions.push(session);
    }
    fn parsers() -> retina_core::protocols::stream::ParserRegistry {
        retina_core::protocols::stream::ParserRegistry::from_strings(
            vec!["tls", "dns", "http", "quic"]
        )
    }
}
pub fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {

    fn packet_continue(
        _mbuf: &retina_core::Mbuf,
        _core_id: &retina_core::CoreId,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        result.data |= retina_core::filter::actions::ActionData::PacketContinue;
        result
    }

    fn packet_filter(mbuf: &retina_core::Mbuf) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        if let Ok(_ethernet) = &retina_core::protocols::packet::Packet::parse_to::<
            retina_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            result.data |= retina_core::filter::actions::ActionData::ProtoFilter |
                    retina_core::filter::actions::ActionData::PacketTrack;
        }
        result
    }
    fn protocol_filter(
        conn: &retina_core::protocols::ConnData,
        tracked: &mut TrackedWrapper,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        if match conn.service() {
            retina_core::protocols::stream::ConnParser::Dns { .. } => true,
            _ => false,
        } {
            return Actions::new();
        } else if match conn.service() {
            retina_core::protocols::stream::ConnParser::Http { .. } => true,
            _ => false,
        } {
            return retina_core::filter::Actions::new();
        } else if match conn.service() {
            retina_core::protocols::stream::ConnParser::Tls { .. } => true,
            _ => false,
        } {
            return retina_core::filter::Actions::new();
        } else if match conn.service() {
            retina_core::protocols::stream::ConnParser::Quic { .. } => true,
            _ => false,
        } {
            return retina_core::filter::Actions::new();
        } else {
            let core_id = tracked.core_id.clone();
            for mbuf in tracked.packets_owned().drain(..) {
                callback(mbuf, core_id);
            }
            // Force connection_deliver to be called
            // Since `track_packet` is called after `packet_deliver`, this will ensure
            // that the last packet in the connection is delivered
            result.add_actions(
                &Actions {
                    data: ActionData::PacketTrack | ActionData::ConnDeliver,
                    terminal_actions: ActionData::PacketTrack| ActionData::ConnDeliver
                },
            )
        }
        result
    }

    fn session_filter(
        _session: &retina_core::protocols::Session,
        _conn: &retina_core::protocols::ConnData,
        _tracked: &mut TrackedWrapper,
    ) -> Actions {
        retina_core::filter::Actions::new()
    }

    fn packet_deliver(
        _mbuf: &retina_core::Mbuf,
        _conn: &retina_core::protocols::ConnData,
        tracked: &mut TrackedWrapper,
    ) {
        let core_id = tracked.core_id.clone();
        for mbuf in tracked.packets_owned().drain(..) {
            callback(mbuf, core_id);
        }
    }

    fn connection_deliver(
        _conn: &retina_core::protocols::ConnData,
        tracked: &mut TrackedWrapper,
    ) {
        let core_id = tracked.core_id.clone();
        for mbuf in tracked.packets_owned().drain(..) {
            callback(mbuf, core_id);
        }
    }
    retina_core::filter::FilterFactory::new(
        "tcp or udp",
        packet_continue,
        packet_filter,
        protocol_filter,
        session_filter,
        packet_deliver,
        connection_deliver,
    )
}
