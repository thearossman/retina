use retina_core::config::load_config;
use retina_core::rte_rdtsc;
use retina_core::subscription::*;
use retina_core::Runtime;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(short, long)]
    spin: u64,
}

// Filter manually defined below to support "filtering out"
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let cycles = args.spin;
    let callback = |_: Connection| {
        spin(cycles);
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();
    Ok(())
}

#[inline]
fn spin(cycles: u64) {
    if cycles == 0 {
        return;
    }
    let start = unsafe { rte_rdtsc() };
    loop {
        let now = unsafe { rte_rdtsc() };
        if now - start > cycles {
            break;
        }
    }
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
                    // \note using arbitrary filter ptree node IDs
                    return FilterResult::MatchNonTerminal(2);
                
                } else if let Ok(udp)
                    = &retina_core::protocols::packet::Packet::parse_to::<Udp,>(ipv4) {
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

    // Arbitrary
    const CONN_TERM_NODE: usize = 3;

    #[inline]
    fn connection_filter(
        conn: &ConnData,
    ) -> FilterResult {
        // Connection filter applied once protocol is identified
        match conn.pkt_term_node {
            _ => {
                match conn.service() {
                    // Return NoMatch for all known encrypted protocols
                    ConnParser::Dns { .. } => { return FilterResult::NoMatch; }
                    ConnParser::Quic { .. } => { return FilterResult::NoMatch; }
                    ConnParser::Tls { .. } => { return FilterResult::NoMatch; }
                    // HTTP or unknown protocol
                    _ => { return FilterResult::MatchTerminal(CONN_TERM_NODE); } 
                }
            }
        }
    }

    #[inline]
    fn session_filter(
        _session: &retina_core::protocols::stream::Session,
        idx: usize,
    ) -> bool {
        // If session filter is applied, connection filter returned a match.
        match idx {
            CONN_TERM_NODE => { return true; }
            _ => { return false; }
        }
    }
    FilterFactory::new(
        /* Hacky way to get: 
         * - Hardware support on NIC (non-TCP/UDP will be dropped)
         * - Correct application-layer parsers added to runtime 
         *   for protocol identification. */
        "(http or dns or tls or quic)",
        packet_filter,
        connection_filter,
        session_filter,
    )
}