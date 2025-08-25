#![recursion_limit = "256"]

use clap::Parser;
use retina_core::subscription::*;
use retina_core::{Runtime, config::load_config};
use retina_filtergen::filter;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

#[allow(dead_code)]
fn callback_http(_http: HttpTransaction) {
    // println!("{:?}", http);
}

fn all_subscribable_types() -> SubscribableTypes {
    SubscribableTypes {
        subscriptions: vec![
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
            SubscribableTypeId::HttpTransaction,
        ],
    }
}

fn all_callbacks() -> SubscribedCallbacks {
    SubscribedCallbacks {
        callbacks: vec![
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
            Box::new(|d| {
                if let SubscribedData::HttpTransaction(http) = d {
                    callback_http(http);
                }
            }),
        ],
    }
}

#[filter(
    "http.host ~ '(?:^|\\.)google\\.com$'
http.host ~ '(?:^|\\.)youtube\\.com$'
http.host ~ '(?:^|\\.)instagram\\.com$'
http.host ~ '(?:^|\\.)linkedin\\.com$'
http.host ~ '(?:^|\\.)microsoft\\.com$'
http.host ~ '(?:^|\\.)amazon\\.com$'
http.host ~ '(?:^|\\.)apple\\.com$'
http.host ~ '(?:^|\\.)whatsapp\\.com$'
http.host ~ '(?:^|\\.)tiktok\\.com$'
http.host ~ '(?:^|\\.)spotify\\.com$'
http.host ~ '(?:^|\\.)reddit\\.com$'
http.host ~ '(?:^|\\.)archive\\.(?:org|today)$'
http.host ~ '(?:^|\\.)wikipedia\\.org$'
http.host ~ '(?:^|\\.)nginx\\.org$'
http.host ~ '(?:^|\\.)apache\\.org$'
http.host ~ '(?:^|\\.)gstatic\\.com$'
http.host ~ '(?:^|\\.)fbcdn\\.net$'
http.host ~ '(?:^|\\.)cloudflare\\.com$'
http.host ~ '(?:^|\\.)googleapis\\.com$'
http.host ~ '(?:^|\\.)cdn\\.cloudflare\\.net$'
http.host ~ '(?:^|\\.)workers\\.dev$'
http.host ~ '(?:^|\\.)cloudfront\\.net$'
http.host ~ '(?:^|\\.)s3\\.amazonaws\\.com$'
http.host ~ '(?:^|\\.)s3-[a-z0-9-]+\\.amazonaws\\.com$'
http.host ~ '(?:^|\\.)s3-website\\.[a-z0-9-]+\\.amazonaws\\.com$'
http.host ~ '(?:^|\\.)msocdn\\.com$'
http.host ~ '(?:^|\\.)azureedge\\.net$'
http.host ~ '(?:^|\\.)msecnd\\.net$'
http.host ~ '(?:^|\\.)akamai.*'
http.host ~ '(?:^|\\.)fastly\\.net$'
http.host ~ '(?:^|\\.)fastlylb\\.net$'
http.host ~ '(?:^|\\.)cdn\\.jsdelivr.*'
http.host ~ '(?:^|\\.)cdnjs\\.cloudflare\\.com$'
http.host ~ '(?:^|\\.)cdn\\.digitaloceanspaces\\.com$'"
)]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let cfg = load_config(&args.config);
    let callbacks = all_callbacks();
    assert!(callbacks.callbacks.len() == 34);
    let subscribable_types = all_subscribable_types();
    assert!(subscribable_types.subscriptions.len() == 34);
    let mut runtime = Runtime::new(cfg, filter, callbacks, subscribable_types).unwrap();
    runtime.run();
}
