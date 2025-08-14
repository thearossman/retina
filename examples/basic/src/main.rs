use retina_core::{config::default_config, subscription::FilterResult, L4Pdu, Runtime};
use retina_datatypes::{ConnRecord, TlsHandshake};
use retina_filtergen::{callback, filter, filter_group, input_files, retina_main};

// TODO better way to specify imports required by generated code
// (This is req'd because ConnRecord is requested as a param)
use retina_core::subscription::{StreamingFilter, Tracked};
use retina_datatypes::FromSession;

#[derive(Debug)]
#[filter]
struct ConnLen {
    len: usize,
}

impl StreamingFilter for ConnLen {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { len: 0 }
    }
    fn clear(&mut self) {}
}

impl ConnLen {
    #[filter_group("ConnLen,level=L4InPayload")]
    fn update(&mut self, _: &L4Pdu) -> FilterResult {
        self.len += 1;
        if self.len > 10 {
            return FilterResult::Accept;
        }
        FilterResult::Continue
    }
}

#[callback("tls and ConnLen,level=L4Terminated")]
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
