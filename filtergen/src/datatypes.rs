use regex::Regex;
use retina_core::filter::{DataType, Level};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, hash_map::Entry};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::Mutex;

static DATATYPES: OnceLock<Mutex<HashMap<String, DataType>>> = OnceLock::new();

lazy_static! {
    // Look for
    pub(crate) static ref RE: Regex = Regex::new(r"(?i)(level|parsers|properties)=([^+;]+)").unwrap();
}

lazy_static! {
    pub(crate) static ref DATATYPES_FP: PathBuf = {
        let target_dir = std::env::current_dir()
            .expect("Cannot get CWD")
            .join("target");
        assert!(
            target_dir.exists(),
            "Cannot find target directory in {}",
            target_dir.display()
        );

        target_dir.join("datatypes.jsonl")
    };
}

pub(crate) fn datatypes() -> &'static Mutex<HashMap<String, DataType>> {
    DATATYPES.get_or_init(|| {
        // Build data from scratch
        if !DATATYPES_FP.exists() {
            return Mutex::new(HashMap::new());
        }
        // Update file
        let file = std::fs::File::open(DATATYPES_FP.clone())
            .expect(&format!("Cannot open {}", DATATYPES_FP.display()));
        let reader = std::io::BufReader::new(file);
        Mutex::new(
            serde_json::from_reader(reader)
                .expect(&format!("Cannot parse {}", DATATYPES_FP.display()))
        )
    })
}

pub(crate) fn add_properties(name: &str, properties: &str) {
    let mut datatypes = datatypes().lock().unwrap();

    let mut level = None;
    let mut parsers = None;
    let mut ops = None;
    for cap in RE.captures_iter(properties) {
        let key = cap[1].to_string().to_lowercase();
        let value = cap[2].to_string();
        if key == "level" {
            level = Some(value);
        } else if key == "parsers" {
            parsers = Some(value.split(',').map(String::from).collect::<Vec<_>>());
        } else if key == "properties" {
            ops = Some(value.split(',').map(String::from).collect::<Vec<_>>());
        }
    }

    let datatype = DataType::from_strings(
        level.expect(&format!("Datatype {} needs Level and Properties specifications", name)),
        ops.expect(&format!("Datatype {} needs Level and Properties specifications", name)),
        parsers,
        name
    );

    match datatypes.entry(name.to_string()) {
        // Update datatype (or no-op)
        Entry::Occupied(mut entry) => {
            if entry.get() != &datatype {
                println!("Updating datatype {}", name);
                entry.insert(datatype);
            }
        }
        // Insert datatype
        Entry::Vacant(entry) => {
            println!("Adding datatype {}", name);
            entry.insert(datatype);
        }
    }

    // Write datatypes to file
    // TMP - obviously can't overwrite the file every time
    let file = std::fs::File::create(DATATYPES_FP.clone())
        .expect(&format!("Cannot create {}", DATATYPES_FP.display()));
    serde_json::to_writer(file, &*datatypes)
        .expect(&format!("Cannot write to {}", DATATYPES_FP.display()));

}
