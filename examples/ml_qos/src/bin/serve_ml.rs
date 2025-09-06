use ml_qos::features::FeatureChunk;
use retina_core::L4Pdu;
use retina_core::Runtime;
use retina_core::StateTxData;
use retina_core::config::load_config;
use retina_core::subscription::StreamingCallback;
use retina_filtergen::*;

use std::fs::File;
// use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::linalg::basic::matrix::DenseMatrix;

#[callback("tls and file=$RETINA_HOME/examples/ml_qos/snis.txt,level=L4InPayload")]
#[derive(Debug, Serialize)]
struct Predictor {
    labels: Vec<usize>,
}

impl StreamingCallback for Predictor {
    fn new(_first_pkt: &L4Pdu) -> Predictor {
        Self { labels: Vec::new() }
    }
    fn clear(&mut self) {
        self.labels.clear();
    }
}

impl Predictor {
    #[callback_group("Predictor,level=L4InPayload")]
    fn update(&mut self, tracked: &FeatureChunk) -> bool {
        if !tracked.ready {
            return true; // continue receiving data
        }
        let feature_vec = tracked.to_feature_vec();
        if let Ok(instance) = DenseMatrix::new(1, feature_vec.len(), feature_vec, false) {
            let mut pred = CLF.predict(&instance).unwrap();
            assert!(pred.len() == 1);
            self.labels.push(pred.pop().unwrap());
            N_PREDICTIONS.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    #[callback_group("Predictor,level=L4Terminated")]
    fn conn_done(&mut self, _tx: &StateTxData) -> bool {
        if !self.labels.is_empty() {
            // TODO record results
            N_CONNS.fetch_add(1, Ordering::Relaxed);
        }
        false
    }
}

#[input_files("$RETINA_HOME/datatypes/data.txt")]
#[input_files("$RETINA_HOME/examples/ml_qos/data.txt")]
#[retina_main]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    // let mut outfile = File::create(args.outfile)?;

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter)?;
    runtime.run();

    println!(
        "Done. Processed {:?} connections, {:?} inference.",
        N_CONNS.load(Ordering::Relaxed),
        N_PREDICTIONS.load(Ordering::Relaxed)
    );

    Ok(())
}

// Globals
lazy_static::lazy_static! {
    // Global classifier instance
    static ref CLF: RandomForestClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>> = {
        let args = Args::parse();
        let mut file = File::open(&args.model_file).expect("Failed to open model file");
        let clf: RandomForestClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>> =
            bincode::deserialize_from(&mut file).expect("Failed to deserialize model");
        clf
    };
    // Number of processed connections
    static ref N_CONNS: AtomicUsize = AtomicUsize::new(0);
    // Number of times predictions have been made
    static ref N_PREDICTIONS: AtomicUsize = AtomicUsize::new(0);
    // Global list of results
    // static ref RESULTS: parking_lot::Mutex<Vec<usize>> = parking_lot::Mutex::new(Vec::new());
}

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "CONFIG_FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "MODEL_FILE")]
    model_file: PathBuf,
    // #[clap(short, long, parse(from_os_str), value_name = "OUT_FILE")]
    // outfile: PathBuf,
}
