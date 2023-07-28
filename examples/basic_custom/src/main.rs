use retina_core::config::default_config;
use retina_core::subscription::custom::CustomSubscribable;
use retina_core::Runtime;
use retina_filtergen::filter;

#[filter("tls.sni ~ '^.*\\.com$'")]
fn main() {
    let cfg = default_config();
    let callback = | custom: CustomSubscribable | {
        println!("{:?}", custom);
    };
    let mut runtime = Runtime::new(cfg, filter, callback).unwrap();
    runtime.run();
}