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
);

#[allow(unused)]
fn eth(conn: &Connection) {
    // println!("Conn: {:?}", conn);
    // spin(*CYCLES.read().unwrap());
}

#[retina_main]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    {
        *CYCLES.write().unwrap() = args.spin;
    }
    let mut runtime: Runtime<Connection> = Runtime::new(config, filter, callbacks())?;
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
