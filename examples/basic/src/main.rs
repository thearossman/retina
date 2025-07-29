use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, TlsHandshake};
use retina_filtergen::{callback, retina_main, input_files};

#[callback("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}

#[input_files("$RETINA_HOME/datatypes/data.jsonl")]
#[retina_main]
fn main() {
    let config = default_config();
    // let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    // runtime.run();
}
