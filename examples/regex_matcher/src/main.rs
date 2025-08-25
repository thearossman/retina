#![recursion_limit = "256"]

use retina_core::Runtime;
use retina_core::config::load_config;
use retina_core::rte_rdtsc;
use retina_core::subscription::{SubscribableWrapper, Subscribed};
use retina_filtergen::retina_main;
use std::path::PathBuf;

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

fn callback_http(_data: Subscribed) {}

#[retina_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribableWrapper> =
        Runtime::new(config, filter, callbacks()).unwrap();
    runtime.run();
}
