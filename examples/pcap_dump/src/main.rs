use retina_core::config::load_config;
use retina_core::subscription::ConnectionFrame;
use retina_core::Runtime;
#[allow(unused_imports)]
use retina_filtergen::filter;

use std::fs::File;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use clap::Parser;
use pcap_file::pcap::PcapWriter;

use pnet::packet::ethernet::MutableEthernetPacket as PnetEthernet;
use pnet::packet::ipv4::MutableIpv4Packet as PnetIpv4;
use pnet::packet::MutablePacket;
use pnet::packet::Packet as PnetPacket;


/* Parsing arguments. Usage: 
 * --config configs/online.toml --outfile my_pcap.pcap
 * \note `outfile` arg is optional; defaults to dump.pcap */
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "dump.pcap"
    )]
    outfile: PathBuf,
}

/*
 * Usually in Retina, you'd define a filter as a string on the top of your
 * main function (#[filter("tcp.port = 80")], for example).
 * However, original Retina doesn't have a way to filter for "not a protocol",
 * so I'm instead writing a manual filter set below to filter out protocols that
 * we know.
 */
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let file = File::create(&args.outfile)?;
    let pcap_writer = Mutex::new(PcapWriter::new(file)?);
    /* Change this key before running on live traffic.
     * The key must be 16 characters.
     * If you get a "could not convert slice to array" error, then
     * the length of your string input is wrong. */
    let key: [u8; 16] = "a sample enc key".as_bytes().try_into()?;

    /* Encrypting MAC addresses is overkill at this stage. Repeated MAC addresses
     * won't mess up flow identification. */
    let const_src = pnet::util::MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1);
    let const_dst = pnet::util::MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf2);

    let callback = |pkt: ConnectionFrame| {
        /* \note Using a Frame type here -- essentially, a raw vector of data --
        * will force a copy. The alternative is manipulating raw (unsafe) pointers,
        * which I'd prefer not to do unless it's really needed. */
        let data = pkt.data;
        let len = data.len();
        if let Some(mut eth) = PnetEthernet::owned(data) {
            let payload = PnetEthernet::payload_mut(&mut eth);
            if let Some(mut ipv4) = PnetIpv4::new(payload) {
                // Anonymize IP addresses
                let src_anon = ipcrypt::encrypt(PnetIpv4::get_source(&ipv4), &key);
                let dst_anon = ipcrypt::encrypt(PnetIpv4::get_destination(&ipv4), &key);
                PnetIpv4::set_source(&mut ipv4, src_anon);
                PnetIpv4::set_destination(&mut ipv4, dst_anon);

                // Clear out MAC addresses
                PnetEthernet::set_source(&mut eth, const_src);
                PnetEthernet::set_destination(&mut eth, const_dst);

                // Write raw data to pcap
                let pkt = eth.packet();
                let mut pcap_writer = pcap_writer.lock().unwrap();
                pcap_writer
                    .write(1, 0, pkt, len as u32)
                    .unwrap();
            }
        }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();
    Ok(())
}

/* Manual filter definition to support "not" */

use retina_core::filter::FilterResult;
use retina_core::Mbuf;
use retina_core::protocols::packet::{ethernet::Ethernet, 
                                     ipv4::Ipv4, ipv6::Ipv6, 
                                     tcp::Tcp, udp::Udp};
use retina_core::protocols::stream::{ConnData, ConnParser};
use retina_core::filter::FilterFactory;

fn filter() -> retina_core::filter::FilterFactory {

    // Applied to each packet
    #[inline]
    #[allow(unused_variables)]
    fn packet_filter(mbuf: &Mbuf) -> FilterResult {
        if let Ok(ethernet)
            = &retina_core::protocols::packet::Packet::parse_to::<Ethernet,>(mbuf) {
            if let Ok(ipv4)
                = &retina_core::protocols::packet::Packet::parse_to::<Ipv4,>(ethernet) {
                
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<Tcp,>(ipv4) {
                    /* To add port filters (e.g., exclude port 80), use the following:
                       Make sure to add for IPv6 too. 
                       The same applies for UDP.
                    if tcp.src_port() == 80 || tcp.dst_port() == 80 {
                        return FilterResult::NoMatch;
                    }
                       See below for needed changes to the connection filter to support
                       port matches.
                     */
                    /* Nonterminal match = future condition needs to be checked.
                     * Returned with the ID of the node on the "filter tree".
                     * For DIY filters, don't worry about the nodes. */
                    return FilterResult::MatchNonTerminal(2);
                
                } else if let Ok(udp)
                    = &retina_core::protocols::packet::Packet::parse_to::<Udp,>(ipv4) {
                    // \optional, filter for UDP ports here
                    return FilterResult::MatchNonTerminal(7);
                }
            } else if let Ok(ipv6)
                = &retina_core::protocols::packet::Packet::parse_to::<Ipv6,>(ethernet) {
                
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<Tcp,>(ipv6) {
                    return FilterResult::MatchNonTerminal(12);
                
                } else if let Ok(udp)
                    = &retina_core::protocols::packet::Packet::parse_to::<Udp,>(ipv6) {
                    return FilterResult::MatchNonTerminal(17);
                }
            }
        }
        return FilterResult::NoMatch;
    }

    #[inline]
    fn connection_filter(
        conn: &ConnData,
    ) -> FilterResult {
        // Connection filter applied once protocol is identified
        match conn.pkt_term_node {
            /* If adding tcp/udp ports, use a unique node ID in the terminal match.
             * E.g., return `FilterResult::MatchTerminal(1);`
             * Then add a match branch for that, returning the same value: 
            1 => {
                return FilterResult::MatchTerminal(1);
            }
             */
            _ => {
                match conn.service() {
                    ConnParser::Dns { .. } => { return FilterResult::NoMatch; }
                    ConnParser::Http { .. } => { return FilterResult::NoMatch; }
                    ConnParser::Quic { .. } => { return FilterResult::NoMatch; }
                    ConnParser::Tls { .. } => { return FilterResult::NoMatch; }
                    ConnParser::Unknown => { return FilterResult::MatchTerminal(3); }
                }
            }
        }
    }

    #[inline]
    fn session_filter(
        _session: &retina_core::protocols::stream::Session,
        _idx: usize,
    ) -> bool {
        // If session filter is applied, connection filter returned a match.
        println!("Session"); 
        true
    }
    FilterFactory::new(
        /* 
         * This will do the following:
         * - For features that can be determined at packet layer: 
         *   inserted into NIC at hardware filter. (E.g.: TCP/UDP port.)
         *   Only relevant if not flow-sampling.
         * - For application-layer protocols: the application-layer parsers  
         *   that will be required for this filter. 
         *   This will not be used as the actual filter, so all we need to do is
         *   name the protocols we want excluded. 
         */
        "(http or dns or tls or quic) or (tcp or udp)",
        packet_filter,
        connection_filter,
        session_filter,
    )
}