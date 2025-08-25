use clap::Parser;
use regex::{RegexSet, SetMatches};
use std::path::PathBuf;

use retina_core::protocols::{Session, stream::SessionData};
use retina_core::subscription::FilterResult;
use retina_core::{Runtime, config::load_config};
use retina_datatypes::HttpTransaction;
use retina_filtergen::{callback, datatype, datatype_group, filter, input_files, retina_main};

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}

lazy_static::lazy_static! {
    static ref REGEX: RegexSet = RegexSet::new(&[
        r"(?:^|\.)google\.com$",
        r"(?:^|\.)youtube\.com$",
        r"(?:^|\.)instagram\.com$",
        r"(?:^|\.)linkedin\.com$",
        r"(?:^|\.)microsoft\.com$",
        r"(?:^|\.)amazon\.com$",
        r"(?:^|\.)apple\.com$",
        r"(?:^|\.)whatsapp\.com$",
        r"(?:^|\.)tiktok\.com$",
        r"(?:^|\.)spotify\.com$",
        r"(?:^|\.)reddit\.com$",

        r"(?:^|\.)archive\.(?:org|today)$",
        r"(?:^|\.)wikipedia\.org$",
        r"(?:^|\.)nginx\.org$",
        r"(?:^|\.)apache\.org$",

        r"(?:^|\.)gstatic\.com$",
        r"(?:^|\.)fbcdn\.net$",
        r"(?:^|\.)cloudflare\.com$",
        r"(?:^|\.)googleapis\.com$",
        r"(?:^|\.)cdn\.cloudflare\.net$",
        r"(?:^|\.)workers\.dev$",
        r"(?:^|\.)cloudfront\.net$",
        r"(?:^|\.)s3\.amazonaws\.com$",
        r"(?:^|\.)s3-[a-z0-9-]+\.amazonaws\.com$",
        r"(?:^|\.)s3-website\.[a-z0-9-]+\.amazonaws\.com$",
        r"(?:^|\.)msocdn\.com$",
        r"(?:^|\.)azureedge\.net$",
        r"(?:^|\.)msecnd\.net$",
        r"(?:^|\.)akamai.*",
        r"(?:^|\.)fastly\.net$",
        r"(?:^|\.)fastlylb\.net$",
        r"(?:^|\.)cdn\.jsdelivr.*",
        r"(?:^|\.)cdnjs\.cloudflare\.com$",
        r"(?:^|\.)cdn\.digitaloceanspaces\.com$",
    ]).unwrap();
}

#[datatype("level=L7EndHdrs")]
struct HttpHostMatch {
    ids: Option<SetMatches>,
}

impl HttpHostMatch {
    #[datatype_group("HttpHostMatch,level=L7EndHdrs")]
    fn new(session: &Session) -> Self {
        if let SessionData::Http(http) = &session.data {
            if let Some(host) = &http.request.host {
                return Self {
                    ids: Some(REGEX.matches(host)),
                };
            }
        }
        return Self { ids: None };
    }
}

#[filter("level=L7EndHdrs")]
fn matches_any(matches: &HttpHostMatch) -> FilterResult {
    match &matches.ids {
        Some(ids) => match ids.matched_any() {
            true => FilterResult::Accept,
            false => FilterResult::Drop,
        },
        None => FilterResult::Drop,
    }
}

#[callback("http and matches_any")]
fn callback(_matches: &HttpHostMatch, _txn: &HttpTransaction) {}

#[input_files("$RETINA_HOME/datatypes/data.txt")]
#[retina_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
