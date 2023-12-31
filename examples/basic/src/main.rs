use retina_core::config::load_config;
use retina_core::subscription::{Subscribed, SubscribableWrapper};
use retina_core::Runtime;
use retina_filtergen::retina_main;
use std::path::PathBuf;
use retina_core::rte_rdtsc;

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short, 
        long, 
        parse(from_os_str), 
        value_name = "FILE",
        default_value = "configs/online.toml"
    )]
    config: PathBuf,
}

#[allow(unused)]
fn no_op(_data: Subscribed) { }

#[allow(unused)]
fn callback1(_data: Subscribed) {
    let start = unsafe { rte_rdtsc() };
    loop {
        let now = unsafe { rte_rdtsc() };
        if now - start > 10000 {
            break;
        }
    }
}

#[retina_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribableWrapper> = Runtime::new(config, filter, 
                                                    callbacks()).unwrap();  
    runtime.run();
}