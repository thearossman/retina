use bindgen::Builder;
use std::env;
use std::path::Path;
use std::process::exit;
use std::process::Command;
use serde_yaml::{Value, from_reader};
use std::collections::HashMap;

fn main() {
    // modified from https://github.com/deeptir18/cornflakes/blob/master/cornflakes-libos/build.rs

    println!("cargo:rerun-if-env-changed=DPDK_PATH");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/dpdk/inline.c");
    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    build_custom_subscription();

    let cargo_dir = Path::new(&cargo_manifest_dir);

    let out_dir_s = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_s);
    let load_lib_path_s = env::var("LD_LIBRARY_PATH").unwrap();
    let load_lib_path = Path::new(&load_lib_path_s);
    let pkg_config_path = load_lib_path.join("pkgconfig");
    let cflags_bytes = Command::new("pkg-config")
        .env("PKG_CONFIG_PATH", &pkg_config_path)
        .args(["--cflags", "libdpdk"])
        .output()
        .unwrap_or_else(|e| panic!("Failed pkg-config cflags: {:?}", e))
        .stdout;
    let cflags = String::from_utf8(cflags_bytes).unwrap();

    let mut header_locations = vec![];

    for flag in cflags.split(' ') {
        if let Some(stripped) = flag.strip_prefix("-I") {
            let header_location = stripped.trim();
            header_locations.push(header_location);
        }
    }

    let ldflags_bytes = Command::new("pkg-config")
        .env("PKG_CONFIG_PATH", &pkg_config_path)
        .args(["--libs", "libdpdk"])
        .output()
        .unwrap_or_else(|e| panic!("Failed pkg-config ldflags: {:?}", e))
        .stdout;

    if ldflags_bytes.is_empty() {
        println!("Could not get DPDK's LDFLAGS. Are DPDK_PATH, LD_LIBRARY_PATH set correctly?");
        exit(1);
    };

    let ldflags = String::from_utf8(ldflags_bytes).unwrap();

    let mut library_location = None;
    let mut lib_names = vec![];

    for flag in ldflags.split(' ') {
        if let Some(stripped) = flag.strip_prefix("-L") {
            library_location = Some(stripped);
        } else if let Some(stripped) = flag.strip_prefix("-l") {
            lib_names.push(stripped);
        }
    }

    // Link in `librte_net_mlx5` and its dependencies if desired.
    #[cfg(feature = "mlx5")]
    {
        lib_names.extend(&[
            "rte_net_mlx5",
            "rte_bus_pci",
            "rte_bus_vdev",
            "rte_common_mlx5",
        ]);
    }

    // Step 1: Now that we've compiled and installed DPDK, point cargo to the libraries.
    println!(
        "cargo:rustc-link-search=native={}",
        library_location.unwrap()
    );
    for lib_name in &lib_names {
        println!("cargo:rustc-link-lib={}", lib_name);
    }

    // Step 2: Generate bindings for the DPDK headers.
    let mut builder = Builder::default();
    for header_location in &header_locations {
        builder = builder.clang_arg(&format!("-I{}", header_location));
    }

    let headers_file = Path::new(&cargo_dir)
        .join("src")
        .join("dpdk")
        .join("dpdk_headers.h");
    let bindings = builder
        .header(headers_file.to_str().unwrap())
        // mark as opaque per bindgen bug on packed+aligned structs:
        // https://github.com/rust-lang/rust-bindgen/issues/1538
        .opaque_type(r"rte_arp_ipv4|rte_arp_hdr")
        .opaque_type(r"(rte_ecpri|rte_l2tpv2)_.*")
        .allowlist_type(r"(rte|eth|pcap)_.*")
        .allowlist_function(r"(_rte|rte|eth|numa|pcap)_.*")
        .allowlist_var(r"(RTE|DEV|ETH|MEMPOOL|PKT|rte)_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap_or_else(|e| panic!("Failed to generate bindings: {:?}", e));
    let bindings_out = out_dir.join("dpdk.rs");
    bindings
        .write_to_file(bindings_out)
        .expect("Failed to write bindings");

    // Step 3: Compile a stub file so Rust can access `inline` functions in the headers
    // that aren't compiled into the libraries.
    let mut builder = cc::Build::new();
    builder.opt_level(3);
    builder.pic(true);
    builder.flag("-march=native");

    let inlined_file = Path::new(&cargo_dir)
        .join("src")
        .join("dpdk")
        .join("inlined.c");
    builder.file(inlined_file.to_str().unwrap());
    for header_location in &header_locations {
        builder.include(header_location);
    }
    builder.compile("inlined");
}


struct ConfigBuilder {
    _grammar: HashMap<String, Vec<String>>,
    cfgs: Vec<(String, String)>,
    raw_data: Value,
}

impl ConfigBuilder {
    pub fn new(filepath_grammar: &str, filepath_in: &str) -> Self {
        let f_in = std::fs::File::open(filepath_in);
        if let Err(e) = f_in {
            panic!("Failed to read config filepath ({}) {:?}", filepath_in, e);
        }

        let f_grammar = std::fs::File::open(filepath_grammar);
        if let Err(e) = f_grammar {
            panic!("Failed to read grammar filepath ({}) {:?}", filepath_grammar, e);
        }

        let data_in = from_reader(f_in.unwrap());
        if let Err(e) = data_in {
            panic!("{:?}", e);
        }

        // let data_grammar = from_reader(f_grammar.unwrap());

        ConfigBuilder {
            _grammar: HashMap::new(), // TODO
            cfgs: Vec::new(),
            raw_data: data_in.unwrap(),
        }
    }

    pub fn parse(&mut self) {
        if self.raw_data.get("subscribed").is_none() {
            panic!("Must specify at least one \"subscribed\" category");
        }
        // TODO: get around cloning (cell, ref, etc.)
        let subscribed_types = self.raw_data.get("subscribed").unwrap().clone();
        self.parse_nested("subscribed", subscribed_types.clone());
    }

    fn parse_nested(&mut self, outer_key: &str, data: serde_yaml::Value) {
        if !data.is_mapping() {
            panic!("Yaml may be incorrectly formatted; must be parseble as mapping {:?}", data);
        }

        let iter = data.as_mapping().unwrap().iter();
        for (inner_key, value) in iter {
            self.cfgs.push((outer_key.to_string(), 
                         inner_key.as_str().unwrap().to_string()));
            if !value.is_null() {
                self.parse_nested( inner_key.as_str().unwrap(), value.clone());
            }
        }
    }

    pub fn print_configs(&self) {
        let prefix = "cargo:rustc-cfg";
        for (key, value) in &self.cfgs {
            println!("{}={}=\"{}\"", prefix, key, value);
        }
    }

}

fn build_custom_subscription() {
    // temp 
    let fp_grammar = "/home/trossman/retina/build_data/grammar.yml";
    let fp_cfgs = "/home/trossman/retina/build_data/custom_cfgs.yml";
    let mut builder = ConfigBuilder::new(fp_grammar, fp_cfgs);
    builder.parse();
    builder.print_configs();
}

/*
fn build_custom_subscription_manual() {
    // TODO - read from custom_defs (constants) and user config file

    println!("cargo:rustc-cfg=subscribed=\"connection\"");
    println!("cargo:rustc-cfg=subscribed=\"frame\"");
    println!("cargo:rustc-cfg=subscribed=\"application\"");
    println!("cargo:rustc-cfg=frame=\"frame\"");
    println!("cargo:rustc-cfg=frame=\"zc_frame\"");
    println!("cargo:rustc-cfg=connection=\"five_tuple\"");
    println!("cargo:rustc-cfg=connection=\"timing\"");
    println!("cargo:rustc-cfg=timing=\"ts_first\"");
    println!("cargo:rustc-cfg=timing=\"time_to_second_packet\"");
    println!("cargo:rustc-cfg=timing=\"max_inactivity\"");
    println!("cargo:rustc-cfg=timing=\"duration\"");
    println!("cargo:rustc-cfg=application=\"dns\"");
    println!("cargo:rustc-cfg=application=\"tls\"");
    println!("cargo:rustc-cfg=application=\"http\"");

    println!("cargo:rustc-cfg=dns=\"transaction_id\"");
    println!("cargo:rustc-cfg=dns=\"dns_query\"");
    println!("cargo:rustc-cfg=dns=\"dns_response\"");
    println!("cargo:rustc-cfg=dns_query=\"num_questions\"");
    println!("cargo:rustc-cfg=dns_query=\"recursion_desired\"");
    println!("cargo:rustc-cfg=dns_query=\"queries\"");
    println!("cargo:rustc-cfg=dns_response=\"response_code\"");
    println!("cargo:rustc-cfg=dns_response=\"authoritative\"");
    println!("cargo:rustc-cfg=dns_response=\"recursion_available\"");
    println!("cargo:rustc-cfg=dns_response=\"num_answers\"");
    println!("cargo:rustc-cfg=dns_response=\"num_additional\"");
    println!("cargo:rustc-cfg=dns_response=\"num_nameservers\"");
    println!("cargo:rustc-cfg=dns_response=\"answers\"");
    println!("cargo:rustc-cfg=dns_response=\"nameservers\"");
    println!("cargo:rustc-cfg=dns_response=\"additionals\"");

    println!("cargo:rustc-cfg=tls=\"client_hello\"");
    println!("cargo:rustc-cfg=tls=\"server_hello\"");
    println!("cargo:rustc-cfg=tls=\"server_certificates\"");
    println!("cargo:rustc-cfg=tls=\"client_certificates\"");
    println!("cargo:rustc-cfg=tls=\"server_key_exchange\"");
    println!("cargo:rustc-cfg=tls=\"client_key_exchange\"");

    println!("cargo:rustc-cfg=http=\"request_data\"");
    println!("cargo:rustc-cfg=http=\"response_data\"");
    println!("cargo:rustc-cfg=http=\"transaction_depth\"");

    println!("cargo:rustc-cfg=http_request=\"method\"");
    println!("cargo:rustc-cfg=http_request=\"uri\"");
    println!("cargo:rustc-cfg=http_request=\"version\"");
    println!("cargo:rustc-cfg=http_request=\"user_agent\"");
    println!("cargo:rustc-cfg=http_request=\"cookie\"");
    println!("cargo:rustc-cfg=http_request=\"host\"");
    println!("cargo:rustc-cfg=http_request=\"content_length\"");
    println!("cargo:rustc-cfg=http_request=\"content_type\"");
    println!("cargo:rustc-cfg=http_request=\"transfer_encoding\"");

    println!("cargo:rustc-cfg=http_response=\"version\"");
    println!("cargo:rustc-cfg=http_response=\"status_code\"");
    println!("cargo:rustc-cfg=http_response=\"status_msg\"");
    println!("cargo:rustc-cfg=http_response=\"content_length\"");
    println!("cargo:rustc-cfg=http_response=\"content_type\"");
    println!("cargo:rustc-cfg=http_response=\"transfer_encoding\"");
}

 */