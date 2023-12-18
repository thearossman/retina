use retina_core::config::load_config;
use retina_core::rte_rdtsc;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_filtergen::retina_main;
#[macro_use]
extern crate lazy_static;
use std::sync::RwLock;

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

lazy_static!(
    static ref CYCLES: RwLock<u64> = RwLock::new(0);
    static ref HTTP: RwLock<u64> = RwLock::new(0);
    static ref TCP80: RwLock<u64> = RwLock::new(0);
    static ref IPDST: RwLock<u64> = RwLock::new(0);
    static ref IPSRC: RwLock<u64> = RwLock::new(0);
    static ref ETH: RwLock<u64> = RwLock::new(0);
);

#[allow(unused)]
fn http(_: Subscribed) {
    spin(*CYCLES.read().unwrap());
    *HTTP.write().unwrap() += 1;
}

#[allow(unused)]
fn tcp_port_80(_: Subscribed) {
    spin(*CYCLES.read().unwrap());
    *TCP80.write().unwrap() += 1;
}

#[allow(unused)]
fn ip_dst(_: Subscribed) {
    spin(*CYCLES.read().unwrap());
    *IPDST.write().unwrap() += 1;
}

#[allow(unused)]
fn ip_src(_: Subscribed) {
    spin(*CYCLES.read().unwrap());
    *IPSRC.write().unwrap() += 1;
}

#[allow(unused)]
fn eth(_: Subscribed) {
    spin(*CYCLES.read().unwrap());
    *ETH.write().unwrap() += 1;
}

#[retina_main]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    {
        *CYCLES.write().unwrap() = args.spin;
    }
    let mut runtime: Runtime<SubscribableWrapper> = Runtime::new(config, filter, callbacks())?;
    runtime.run();
    println!("Called: {} - HTTP, {} - TCP-80, {} - IP-dst, {} - IP-src, {} - Eth", 
             *HTTP.read().unwrap(),
             *TCP80.read().unwrap(),
             *IPDST.read().unwrap(),
             *IPSRC.read().unwrap(),
             *ETH.read().unwrap()); 
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
