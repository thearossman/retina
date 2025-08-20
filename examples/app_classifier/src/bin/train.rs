// Taken from https://github.com/stanford-esrg/cato/tree/cc0ff3c99ce2ad674fd61757611a682008586ee2/scripts/train_rust_dt

use smartcore::dataset::Dataset;
use smartcore::linalg::basic::arrays::{Array, Array2};
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::tree::decision_tree_classifier::{
    DecisionTreeClassifier, DecisionTreeClassifierParameters,
};

use anyhow::{anyhow, Result};
use clap::Parser;
use serde::Serialize;

use std::fs::File;
use std::io::Write;
use std::time::Instant;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, value_name = "TRAIN_DATASET")]
    train_dataset: String,
    #[clap(long, value_name = "TEST_DATASET")]
    test_dataset: String,
    #[clap(long, value_name = "FEATURE_COMMA")]
    feature_comma: String,
    #[clap(long, value_name = "PARAMS")]
    param_max_depth: u16,
    #[clap(long, value_name = "MODEL_PRED")]
    model_pred: String,
    #[clap(long, value_name = "MODEL_BIN")]
    model_bin: String,
}

/// Load preprocessed dataset from CSV and into a smartcore Dataset
fn load_dataset(dataset_file: &str, feature_set: &[&str]) -> Result<Dataset<f64, usize>> {
    println!("Loading dataset: {}", dataset_file);
    let start = Instant::now();
    let mut data: Vec<f64> = vec![];
    let mut target: Vec<usize> = vec![];
    let mut target_names: Vec<usize> = vec![];
    let mut n_rows = 0;
    let mut n_cols = 0;

    let mut rdr = csv::Reader::from_path(dataset_file)?;
    let mut headers: Vec<String> = vec![];
    let mut label_idx = None;
    let mut feature_idx = vec![];
    {
        for (i, header) in rdr.headers()?.iter().enumerate() {
            if header == "label" {
                label_idx = Some(i);
            } else if feature_set.contains(&header) {
                headers.push(header.to_string());
                feature_idx.push(i);
                n_cols += 1;
            }
        }
    }
    let label_idx = label_idx.ok_or(anyhow!("No label."))?;
    for (_row_idx, record) in rdr.records().enumerate() {
        if let Ok(val) = record
            .as_ref()
            .unwrap()
            .get(label_idx)
            .ok_or(anyhow!("No target found."))?
            .parse()
        {
            target.push(val);
            if !target_names.contains(&val) {
                target_names.push(val);
            }
            n_rows += 1;
            for (i, item) in record?.iter().enumerate() {
                if feature_idx.contains(&i) {
                    data.push(item.parse().unwrap_or(0.0));
                }
            }
        }
    }
    println!("Num samples: {}", n_rows);
    println!("Num features: {}", n_cols);
    println!("Num classes: {}", target_names.len());

    let dataset = Dataset {
        data,
        target,
        num_samples: n_rows,
        num_features: n_cols,
        feature_names: headers,
        target_names: target_names.iter().map(|s| s.to_string()).collect(),
        description: dataset_file.to_string(),
    };
    println!("Done loading data, elapsed: {:?}", start.elapsed());
    Ok(dataset)
}

/// Trains a decision tree classifier from dataset
fn train_dt(
    train_dataset: Dataset<f64, usize>,
    params: DecisionTreeClassifierParameters,
) -> Result<DecisionTreeClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>>> {
    println!("Training decision tree classifier with params {:?}", params);
    let x_train = DenseMatrix::new(
        train_dataset.num_samples,
        train_dataset.num_features,
        train_dataset.data,
        false,
    )?;
    let y_train = train_dataset.target;

    let start = Instant::now();
    let clf = DecisionTreeClassifier::fit(&x_train, &y_train, params)?;
    println!("Done training, elapsed: {:?}", start.elapsed());

    Ok(clf)
}

/// Tests decision tree classifier on test set and measures inference times
fn test_dt(
    clf: &DecisionTreeClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>>,
    test_dataset: Dataset<f64, usize>,
) -> ModelPred {
    let x_test = DenseMatrix::new(
        test_dataset.num_samples,
        test_dataset.num_features,
        test_dataset.data,
        false,
    )
    .expect("Failed to build test xdata");
    let y_test = test_dataset.target;
    let (y_hat, y_time) = predict_and_measure_dt(clf, &x_test);
    println!(
        "Mean prediction time: {}",
        y_time.iter().sum::<usize>() as f64 / y_time.len() as f64
    );
    ModelPred::new(y_test, y_hat, y_time)
}

/// Makes per-sample predictions on test set and measures the prediction time per sample.
fn predict_and_measure_dt(
    clf: &DecisionTreeClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>>,
    x_test: &DenseMatrix<f64>,
) -> (Vec<usize>, Vec<usize>) {
    let num_samples = x_test.shape().0;
    let mut y_time = Vec::with_capacity(num_samples);
    let mut y_hat = Vec::with_capacity(num_samples);
    for i in 0..num_samples {
        let row = x_test.get_row(i);
        // DenseMatrix with 1 row
        let instance = DenseMatrix::from_row(row.as_ref());
        let start = Instant::now();
        let pred = clf.predict(&instance).unwrap();
        let elapsed = start.elapsed();
        y_time.push(elapsed.as_nanos() as usize);
        y_hat.extend_from_slice(pred.as_slice());
    }
    (y_hat, y_time)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let train_dataset_fname = args.train_dataset;
    let test_dataset_fname = args.test_dataset;
    let feature_comma = args.feature_comma;
    let param_max_depth = args.param_max_depth;

    let model_pred_fname = args.model_pred;
    let model_bin_fname = args.model_bin;

    let feature_set: Vec<&str> = feature_comma.split(",").collect();

    let train_dataset = load_dataset(&train_dataset_fname, &feature_set)?;
    let test_dataset = load_dataset(&test_dataset_fname, &feature_set)?;

    let mut params = DecisionTreeClassifierParameters::default().with_max_depth(param_max_depth);
    params.seed = Some(0);

    // Train and test
    let clf = train_dt(train_dataset, params)?;
    let model_pred = test_dt(&clf, test_dataset);

    let json = serde_json::to_string(&model_pred).unwrap();
    let mut file = File::create(&model_pred_fname)?;
    file.write_all(json.as_bytes())?;
    println!("Rust model predictions saved to {:?}", model_pred_fname);

    let mut file = File::create(&model_bin_fname)?;
    bincode::serialize_into(&mut file, &clf)?;
    println!("Rust model binary saved to {:?}", model_bin_fname);

    Ok(())
}

/// For evaluating rust model prediction performance and speed
#[derive(Debug, Clone, Serialize)]
struct ModelPred {
    y_test: Vec<usize>,
    y_hat: Vec<usize>,
    y_time: Vec<usize>,
}

impl ModelPred {
    fn new(y_test: Vec<usize>, y_hat: Vec<usize>, y_time: Vec<usize>) -> ModelPred {
        ModelPred {
            y_test,
            y_hat,
            y_time,
        }
    }
}
