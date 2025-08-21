use std::vec;

use retina_core::config::load_config;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_filtergen::filter;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

fn callback1(tls: TlsHandshake) {
    // println!("{:?}", tls);
}

fn callback2(tls: TlsHandshake) {
    // println!("{:?}", tls);
}

fn callback3(http: HttpTransaction) {
    // println!("{:?}", http);
}

fn callback4(conn: Connection) {
    // println!("{:?}", conn);
}

fn all_subscribable_types() -> SubscribableTypes {
    SubscribableTypes {
        subscriptions: vec![
            SubscribableTypeId::TlsHandshake,
            SubscribableTypeId::TlsHandshake,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::Connection,
        ],
    }
}

fn all_callbacks() -> SubscribedCallbacks {
    SubscribedCallbacks {
        callbacks: vec![
            Box::new(|d| {
                if let SubscribedData::TlsHandshake(tls) = d {
                    callback1(tls);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::TlsHandshake(tls) = d {
                    callback2(tls);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback3(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::Connection(conn) = d {
                    callback4(conn);
                }
            }),
        ],
    }
}

#[filter(
    "tls.sni ~ '^.*\\.com$'
tls
http
ipv4"
)]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let cfg = load_config(&args.config);
    let callbacks = all_callbacks();
    let subscribable_types = all_subscribable_types();
    let mut runtime = Runtime::new(cfg, filter, callbacks, subscribable_types).unwrap();
    runtime.run();
}
