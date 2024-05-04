use retina_core::config::load_config;
use retina_core::rte_rdtsc;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_filtergen::filter;
use ipnet::Ipv4Net;
use std::net::IpAddr;

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

#[filter("ipv4.dst_addr = 0.0.0.0/0")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let cycles = args.spin;
    let callback = |conn: Connection| {
        spin_filter(cycles, conn);
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();
    Ok(())
}

#[inline]
fn spin(cycles: u64, _conn: &Connection) {
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

lazy_static::lazy_static! {
    static ref SUBNETS: Vec<Ipv4Net> = vec![
        "0.0.0.0/0".parse().unwrap()
    ];
}

fn spin_filter(cycles: u64, conn: Connection) {
    for subnet in SUBNETS.iter() {
        if let IpAddr::V4(ip) = &conn.five_tuple.resp.ip() {
            if subnet.contains(ip) {
                spin(cycles, &conn);
            }
        }
    }
}