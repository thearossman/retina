use retina_core::config::load_config;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_filtergen::filter;
use hdrhistogram::Histogram;
use retina_core::conntrack::pdu::L4Pdu;
use lazy_static::lazy_static;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "hist.jsonl"
    )]
    outfile: PathBuf,
}

#[derive(Debug)]
struct EntropyHistogram {
    data: Histogram<u64>,
}

lazy_static! { 
    static ref LOG_2: f64 = (2.0 as f64).ln();
    static ref SCALE_FACTOR: f64 = 1_000_000.0;
    static ref SIG_FIG: u8 = 3;
}

fn ideal_entropy(len: f64) -> f64 {
    let prob: f64 = 1.0 / len;
    -1.0 * len * prob * prob.ln() / *LOG_2
}

// Adapted from https://docs.rs/entropy/latest/src/entropy/lib.rs.html#14-33
// and  https://stackoverflow.com/questions/2979174/how-do-i-compute-the-approximate-entropy-of-a-bit-string
fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut entropy = 0.0;
    let len = bytes.len() as f64;
    
    let mut counts = [0; 256];
    let mut probs = [0.0 as f64; 256];
    
    for &b in bytes {
        // Char count per character
        counts[b as usize] += 1;
    }
    for i in 0..256 {
        if counts[i] == 0 {
            continue;
        }
        // (char count of c) / len(byte string)
        probs[i] = counts[i] as f64 / len;
    } 

    for p in probs {
        if p == 0.0 {
            continue;
        }
        // Sum of (p * ln(p) / ln(2)) for each `p`
        let v = p * p.ln() / *LOG_2;
        entropy += v;
    }

    entropy * -1.0
}

impl EntropyHistogram {
    
    pub fn new() -> Self {
        Self {
            data: Histogram::new_with_max(
                *SCALE_FACTOR as u64,
                *SIG_FIG
            ).unwrap(),
        }
    }

    pub fn record(&mut self, pdu: L4Pdu) {
        // Get payload (after TCP/UDP headers)
        let length = pdu.length();
        let offset = pdu.offset(); 
        if let Ok(payload) = pdu.mbuf_own().get_data_slice(offset, length) {

            let actual_entropy = shannon_entropy(payload);
            let ideal = ideal_entropy(length as f64);

            // Can only record u64 to histogram - need to scale
            let mut ratio = actual_entropy / ideal;
            if ratio < 0.0 || ratio > 1.001 { 
                panic!("ENTROPY: {} / {} = {}", actual_entropy, ideal, ratio);
            }
            if ratio > 1.0 {
                ratio = 1.0;
            }
            self.data.record((ratio * *SCALE_FACTOR) as u64).unwrap();
        }
    }

}

#[filter("tls or quic")]
fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let hist = std::sync::Mutex::new(EntropyHistogram::new());
    
    let callback = |frame: ConnectionPdu| {
        hist.lock().unwrap().record(frame.pdu);
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    
    let h = hist.lock().unwrap();
    println!("Mean {}, min {}, max {}", h.data.mean() as f64 / *SCALE_FACTOR, 
                                        h.data.min() as f64 / *SCALE_FACTOR, 
                                        h.data.max() as f64 / *SCALE_FACTOR);
    println!("0.25 {}, 0.5 {}, 0.75 {}, 0.99 {}",
                h.data.value_at_quantile(0.25) as f64 / *SCALE_FACTOR, 
                h.data.value_at_quantile(0.5) as f64 / *SCALE_FACTOR, 
                h.data.value_at_quantile(0.75) as f64 / *SCALE_FACTOR,
                h.data.value_at_quantile(0.99) as f64 / *SCALE_FACTOR);

    println!("Samples recorded {}", h.data.len());
    Ok(())
}


/*
// MANUAL FILTER
// (udp or tcp) and (not tls) and (not quic)

fn filter() -> retina_core::filter::FilterFactory {
    #[inline]
    fn packet_filter(mbuf: &retina_core::Mbuf) -> retina_core::filter::FilterResult {
        if let Ok(ethernet)
            = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ethernet::Ethernet,
            >(mbuf) {
            if let Ok(ipv4)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv4::Ipv4,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv4) {
                    return retina_core::filter::FilterResult::MatchNonTerminal(2);
                } else if let Ok(udp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::udp::Udp,
                    >(ipv4) {
                    return retina_core::filter::FilterResult::MatchNonTerminal(4);
                }
            } else if let Ok(ipv6)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv6::Ipv6,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv6) {
                    return retina_core::filter::FilterResult::MatchNonTerminal(7);
                } else if let Ok(udp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::udp::Udp,
                    >(ipv6) {
                    return retina_core::filter::FilterResult::MatchNonTerminal(9);
                }
            }
        }
        return retina_core::filter::FilterResult::NoMatch;
    }
    #[inline]
    fn connection_filter(
        conn: &retina_core::protocols::stream::ConnData,
    ) -> retina_core::filter::FilterResult {
        if match conn.service() {
            retina_core::protocols::stream::ConnParser::Tls { .. } => true,
            _ => false,
        } {
            return retina_core::filter::FilterResult::NoMatch;
        }
        if match conn.service() {
            retina_core::protocols::stream::ConnParser::Quic { .. } => true,
            _ => false,
        } {
            return retina_core::filter::FilterResult::NoMatch;
        }
        return MatchTerminal(3);
    }
    #[inline]
    fn session_filter(
        session: &retina_core::protocols::stream::Session,
        idx: usize,
    ) -> bool {
        match idx {
            3 => return true,
            5 => return true,
            8 => return true,
            10 => return true,
            _ => return false,
        }
    }
    retina_core::filter::FilterFactory::new(
        "tls or quic",
        packet_filter,
        connection_filter,
        session_filter,
    )
} */
