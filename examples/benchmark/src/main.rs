use clap::Parser;
use retina_core::rte_rdtsc;
use retina_core::{config::load_config, Runtime};
use retina_datatypes::ConnRecord;
use retina_filtergen::*;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value = "0")]
    spin: u64,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/online.toml"
    )]
    config: PathBuf,
}

static SPIN: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
fn spin() {
    let cycles = SPIN.load(Ordering::Relaxed);
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

#[callback("file=$RETINA_HOME/examples/benchmark/filter_strs.txt,level=L4Terminated")]
fn conn_callback(_conn: &ConnRecord) {
    spin();
}

#[input_files("$RETINA_HOME/datatypes/data.txt")]
#[retina_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    SPIN.store(args.spin, Ordering::Relaxed);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
