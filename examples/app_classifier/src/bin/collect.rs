use app_classifier::features::*;
use retina_core::config::load_config;
use retina_core::subscription::StreamingCallback;
use retina_core::L4Pdu;
use retina_core::Runtime;
use retina_datatypes::PktCount;
use retina_datatypes::TlsHandshake;
use retina_filtergen::*;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use clap::Parser;
use serde::Serialize;

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    outfile: PathBuf,
}

lazy_static::lazy_static! {
    static ref COUNT: AtomicUsize = AtomicUsize::new(0);
    static ref FILE: Mutex<BufWriter<File>> = {
        let args = Args::parse();
        let file = File::create(args.outfile).expect("Failed to create output file");
        Mutex::new(BufWriter::new(file))
    };
}

#[derive(Debug)]
#[callback("ipv4 and tcp and tls")]
struct CollectFeatures;

const MAX_PKTS: usize = 50;

#[derive(Debug, Serialize)]
struct LabeledFeatures {
    #[serde(flatten)]
    features: Features,
    label: String,
}

impl StreamingCallback for CollectFeatures {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {}
    }

    fn clear(&mut self) {}
}

impl CollectFeatures {
    #[callback_group("CollectFeatures,level=L4InPayload")]
    fn update(&mut self, npkts: &PktCount, conn: &TrackedFeatures, tls: &TlsHandshake) -> bool {
        if npkts.raw() >= MAX_PKTS {
            self.log_features(conn, tls);
            // Got data for connection
            // Note - where data is collected when training for streaming inference
            // should be more rigorous for a real use-case.
            return false;
        }
        true // continue
    }

    #[callback_group("CollectFeatures,level=L4Terminated")]
    fn terminated(&mut self, npkts: &PktCount, conn: &TrackedFeatures, tls: &TlsHandshake) -> bool {
        if npkts.raw() < MAX_PKTS {
            self.log_features(conn, tls);
        }
        false
    }

    fn log_features(&self, conn: &TrackedFeatures, tls: &TlsHandshake) {
        if let Some(features) = Features::from_tracked(conn) {
            let features = LabeledFeatures {
                features,
                label: sni_to_label(tls.sni()),
            };
            if let Ok(serialized) = serde_json::to_string(&features) {
                // println!("{}", conn);
                let mut wtr = FILE.lock().unwrap();
                wtr.write_all(serialized.as_bytes()).unwrap();
                wtr.write_all(b"\n").unwrap();
                COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[input_files("$RETINA_HOME/datatypes/data.txt")]
#[input_files("$RETINA_HOME/examples/app_classifier/data.txt")]
#[retina_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    println!(
        "Collected features from {} packets.",
        COUNT.load(Ordering::Relaxed)
    );
}
