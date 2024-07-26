use retina_core::config::load_config;
use retina_core::subscription::ConnectionFrame;
use retina_core::Runtime;
#[allow(unused_imports)]
use retina_filtergen::filter;

use std::fs::File;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

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

#[filter("")]
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

    let cnt = AtomicUsize::new(0);

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
                // Counter
                cnt.fetch_add(1, Ordering::Relaxed);
            }
        }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    println!(
        "Done. Logged {:?} packets to {:?}",
        cnt, &args.outfile
    );

    Ok(())
}