use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::vec;
use std::path::PathBuf;

use retina_core::config::load_config;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_core::rte_rdtsc;
use retina_filtergen::filter;

use clap::Parser;

static SPIN: AtomicU64 = AtomicU64::new(0);

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(short, long)]
    spin: u64,
}

#[allow(dead_code)]
fn spin() {
    let cycles = SPIN.load(Ordering::Relaxed);
    if cycles == 0 { return; }
    let start = unsafe { rte_rdtsc() };
    loop {
        let now = unsafe { rte_rdtsc() };
        if now - start > cycles {
            break;
        }
    }
}

#[allow(dead_code)]
fn callback_tls(_tls: TlsHandshake) {
    // println!("{:?}", tls);
}

#[allow(dead_code)]
fn callback_http(_http: HttpTransaction) {
    // println!("{:?}", http);
}

#[allow(dead_code)]
fn callback_dns(_dns: DnsTransaction) {
    // println!("{:?}", dns);
}

#[allow(dead_code)]
fn callback_quic(_quic: QuicStream) {
    // println!("{:?}", quic);
}

#[allow(dead_code)]
fn callback_conn(_conn: Connection) {
    // println!("{:?}", conn);
}

fn all_subscribable_types() -> SubscribableTypes {
    SubscribableTypes {
        subscriptions: vec![
			SubscribableTypeId::Connection,
			SubscribableTypeId::Connection,
		]
    }
}

fn all_callbacks() -> SubscribedCallbacks {
    SubscribedCallbacks {
        callbacks: vec![			Box::new(|d| {
				if let SubscribedData::Connection(conn) = d {
					callback_conn(conn);
				}
			}),
			Box::new(|d| {
				if let SubscribedData::Connection(conn) = d {
					callback_conn(conn);
				}
			}),
		]
    }
}

#[filter("ipv4.addr = 0.0.0.0/1 and (http or tls or dns or quic)
ipv4.addr = 128.0.0.0/1 and (http or tls or dns or quic)
")]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let cfg = load_config(&args.config);
    SPIN.store(args.spin, Ordering::Relaxed);
    let callbacks = all_callbacks();
    let subscribable_types = all_subscribable_types();
    let mut runtime = Runtime::new(cfg, filter, callbacks, subscribable_types).unwrap();
    runtime.run();
}
