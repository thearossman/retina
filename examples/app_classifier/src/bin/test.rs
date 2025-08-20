use app_classifier::features::Features;
use app_classifier::features::TrackedFeatures;
use retina_core::config::load_config;
use retina_core::config::RuntimeConfig;
use retina_core::subscription::StreamingCallback;
use retina_core::L4Pdu;
use retina_core::Runtime;
use retina_filtergen::*;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::linalg::basic::matrix::DenseMatrix;

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "CONFIG_FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "MODEL_FILE")]
    model_file: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "OUT_FILE")]
    outfile: PathBuf,
}

lazy_static::lazy_static! {
    static ref CLF: RandomForestClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>> = {
        let args = Args::parse();
        load_clf(&args.model_file).expect("Failed to load model")
    };
    static ref CNT: AtomicUsize = AtomicUsize::new(0);
}

#[derive(Debug)]
#[callback("ipv4 and tcp and tls")]
struct Predictions {
    labels: Vec<String>,
}

impl StreamingCallback for Predictions {
    fn new(_first_pkt: &L4Pdu) -> Predictions {
        Predictions { labels: Vec::new() }
    }
    fn clear(&mut self) {
        self.labels.clear();
    }
}

impl StreamingCallback {
    #[callback_group("Predictions,level=L4InPayload")]
    fn update(&mut self, tracked: &TrackedFeatures) -> bool {
        if tracked.cnt % 10 != 0 {
            return true; // Continue receiving packets
        }
        if let Some(features) = Features::from_tracked(tracked) {
            let feature_vec = features.feature_vec();
            if let Ok(instance) = DenseMatrix::new(1, feature_vec.len(), feature_vec, false) {
                let pred = CLF.predict(&instance).unwrap();
                CNT.fetch_add(1, Ordering::Relaxed);
                self.labels.push(pred.to_string());
            }
        }
        // Stop after first 100 packets
        if tracked.cnt == 100 {
            // TODO record results
            return false; // Stop receiving packets
        }
    }

    #[callback_group("Predictions,level=L4Terminated")]
    fn conn_done(&mut self, tx: &StateTxData) {
        if !self.labels.is_empty() {
            // TODO record results
        }
    }
}

#[input_files("$RETINA_HOME/datatypes/data.txt")]
#[input_files("$RETINA_HOME/examples/app_classifier/data.txt")]
#[retina_main]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut outfile = File::create(args.outfile)?;
    let mut runtime = Runtime::new(config.clone(), filter)?;
    runtime.run();

    println!(
        "Done. Processed {:?} connections",
        CNT.load(Ordering::Relaxed)
    );
    Ok(())
}
