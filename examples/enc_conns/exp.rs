Parsed datatype: Datatype(DatatypeSpec { name: "FirstPayloadPkt", level: None, expl_parsers: [] })
Caching input in memory
Parsed datatype function: DatatypeFn(DatatypeFnSpec { group_name: "FirstPayloadPkt", func: FnSpec { name: "update", datatypes: ["L4Pdu"], returns: None }, level: [L4InPayload(false)] })
Caching input in memory
Parsed callback: Callback(CallbackFnSpec { filter: "tcp", level: [L4InPayload(false)], func: FnSpec { name: "exempt", datatypes: ["FirstPayloadPkt", "SessionProto"], returns: Bool }, expl_parsers: ["http", "tls"] })
Caching input in memory
Got input from /home/trossman/retina/datatypes/data.txt
Done with macros - beginning code generation

Parsers: http, tls

Tree Per-Packet:
`- ethernet (0)
   |- ipv4 (1)
   |  `- tcp (2)
   `- ipv6 (3)
      `- tcp (4)

Tree L4FirstPacket
,`- 0: ethernet
   |- 1: ipv4 -- A: L4: Actions[Update, PassThrough] (Until:  L4InPayload: Actions[Update, PassThrough], L7OnDisc: Actions[PassThrough]) L7: Actions[Parse] (Until:  L4InPayload: Actions[Parse], L7OnDisc: Actions[Parse])
   `- 2: ipv6 -- A: L4: Actions[Update, PassThrough] (Until:  L4InPayload: Actions[Update, PassThrough], L7OnDisc: Actions[PassThrough]) L7: Actions[Parse] (Until:  L4InPayload: Actions[Parse], L7OnDisc: Actions[Parse]) x

Tree L4InPayload(false)
,`- 0: ethernet -- A: L4: Actions[Update] (Until:  L4InPayload: Actions[Update]) L7: Actions[] (Until: ) D: ( exempt, )
   `- 1: L7=Discovery -- A: L4: Actions[PassThrough] (Until:  L4InPayload: Actions[PassThrough], L7OnDisc: Actions[PassThrough]) L7: Actions[Parse] (Until:  L4InPayload: Actions[Parse], L7OnDisc: Actions[Parse])

#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use clap::Parser;
use retina_core::protocols::packet::tcp::TCP_PROTOCOL;
use retina_core::protocols::stream::SessionProto;
use retina_core::subscription::Tracked;
use retina_core::{config::load_config, L4Pdu, Runtime};
use retina_filtergen::{callback, datatype, datatype_group, input_files, retina_main};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use lazy_static::lazy_static;
#[allow(missing_copy_implementations)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct TOTAL_TCP {
    __private_field: (),
}
#[doc(hidden)]
#[allow(non_upper_case_globals)]
static TOTAL_TCP: TOTAL_TCP = TOTAL_TCP { __private_field: () };
impl ::lazy_static::__Deref for TOTAL_TCP {
    type Target = AtomicUsize;
    fn deref(&self) -> &AtomicUsize {
        #[inline(always)]
        fn __static_ref_initialize() -> AtomicUsize {
            AtomicUsize::new(0)
        }
        #[inline(always)]
        fn __stability() -> &'static AtomicUsize {
            static LAZY: ::lazy_static::lazy::Lazy<AtomicUsize> = ::lazy_static::lazy::Lazy::INIT;
            LAZY.get(__static_ref_initialize)
        }
        __stability()
    }
}
impl ::lazy_static::LazyStatic for TOTAL_TCP {
    fn initialize(lazy: &Self) {
        let _ = &**lazy;
    }
}
#[allow(missing_copy_implementations)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct BLOCKED_TCP {
    __private_field: (),
}
#[doc(hidden)]
#[allow(non_upper_case_globals)]
static BLOCKED_TCP: BLOCKED_TCP = BLOCKED_TCP { __private_field: () };
impl ::lazy_static::__Deref for BLOCKED_TCP {
    type Target = AtomicUsize;
    fn deref(&self) -> &AtomicUsize {
        #[inline(always)]
        fn __static_ref_initialize() -> AtomicUsize {
            AtomicUsize::new(0)
        }
        #[inline(always)]
        fn __stability() -> &'static AtomicUsize {
            static LAZY: ::lazy_static::lazy::Lazy<AtomicUsize> = ::lazy_static::lazy::Lazy::INIT;
            LAZY.get(__static_ref_initialize)
        }
        __stability()
    }
}
impl ::lazy_static::LazyStatic for BLOCKED_TCP {
    fn initialize(lazy: &Self) {
        let _ = &**lazy;
    }
}
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./tests/functionality/basic_test/curr_output.jsonl"
    )]
    outfile: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}
impl clap::Parser for Args {}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
#[allow(deprecated)]
impl clap::CommandFactory for Args {
    fn into_app<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("enc_conns");
        <Self as clap::Args>::augment_args(__clap_app)
    }
    fn into_app_for_update<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("enc_conns");
        <Self as clap::Args>::augment_args_for_update(__clap_app)
    }
}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
impl clap::FromArgMatches for Args {
    fn from_arg_matches(
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        Self::from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn from_arg_matches_mut(
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        #![allow(deprecated)]
        let v = Args {
            outfile: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("outfile")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "outfile",
                            ),
                        );
                        res
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?,
            config: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        );
                        res
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?,
        };
        ::std::result::Result::Ok(v)
    }
    fn update_from_arg_matches(
        &mut self,
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn update_from_arg_matches_mut(
        &mut self,
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        #![allow(deprecated)]
        if __clap_arg_matches.contains_id("outfile") {
            #[allow(non_snake_case)]
            let outfile = &mut self.outfile;
            *outfile = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("outfile")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "outfile",
                            ),
                        );
                        res
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?;
        }
        if __clap_arg_matches.contains_id("config") {
            #[allow(non_snake_case)]
            let config = &mut self.config;
            *config = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        );
                        res
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?;
        }
        ::std::result::Result::Ok(())
    }
}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
impl clap::Args for Args {
    fn augment_args<'b>(__clap_app: clap::Command<'b>) -> clap::Command<'b> {
        {
            let __clap_app = __clap_app;
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("outfile")
                        .takes_value(true)
                        .value_name("OUTFILE")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('o')
                        .long("outfile")
                        .value_name("FILE")
                        .default_value(
                            "./tests/functionality/basic_test/curr_output.jsonl",
                        );
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value("./configs/offline.toml");
                    arg
                });
            __clap_app
        }
    }
    fn augment_args_for_update<'b>(__clap_app: clap::Command<'b>) -> clap::Command<'b> {
        {
            let __clap_app = __clap_app;
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("outfile")
                        .takes_value(true)
                        .value_name("OUTFILE")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('o')
                        .long("outfile")
                        .value_name("FILE")
                        .default_value(
                            "./tests/functionality/basic_test/curr_output.jsonl",
                        );
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value("./configs/offline.toml");
                    arg
                });
            __clap_app
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for Args {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "Args",
            "outfile",
            &self.outfile,
            "config",
            &&self.config,
        )
    }
}
fn bit_length(data: &Vec<u8>) -> f64 {
    (data.len() * 8) as f64
}
fn bit_entropy(data: &Vec<u8>) -> f64 {
    data.iter().map(|&b| b.count_ones()).sum::<u32>() as f64 / bit_length(data)
}
fn pct_matching(data: &Vec<u8>, bytes: &[u8]) -> f64 {
    data.iter().filter(|&b| bytes.contains(b)).count() as f64 / bit_length(data)
}
fn first_n(data: &Vec<u8>, bytes: &[u8], n: usize) -> bool {
    if data.len() < n {
        return false;
    }
    data[..n].iter().all(|&b| bytes.contains(&b))
}
fn count_contiguous(data: &Vec<u8>, bytes: &[u8]) -> usize {
    data.iter()
        .fold(
            (0, 0),
            |(max, curr), &b| {
                if bytes.contains(&b) { (max, curr + 1) } else { (max.max(curr), 0) }
            },
        )
        .0
}
struct FirstPayloadPkt {
    pub(crate) payload: Option<Vec<u8>>,
}
impl Tracked for FirstPayloadPkt {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { payload: None }
    }
    fn update(&mut self, pdu: &L4Pdu) {
        if pdu.ctxt.proto != TCP_PROTOCOL {
            return;
        }
        if self.payload.is_some() {
            return;
        }
        if pdu.length() == 0 {
            return;
        }
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(pdu.offset(), pdu.length()) {
            self.payload = Some(data.to_vec());
        }
    }
    fn phase_tx(&mut self, _tx: &retina_core::StateTxData) {}
    fn clear(&mut self) {
        self.payload = None;
    }
}
fn exempt(pkt: &FirstPayloadPkt, proto: &SessionProto) -> bool {
    TOTAL_TCP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if match proto {
        SessionProto::Tls | SessionProto::Http => true,
        _ => false,
    } {
        return false;
    }
    let data = pkt
        .payload
        .as_ref()
        .expect("FirstPayloadPkt should have a payload if protocol ID'd");
    let entr = bit_entropy(data);
    if entr <= 3.4 || entr >= 4.6 {
        return false;
    }
    if first_n(data, &[0x20, 0x7e], 6) {
        return false;
    }
    if pct_matching(data, &[0x20, 0x7e]) > 0.5 {
        return false;
    }
    if count_contiguous(data, &[0x20, 0x7e]) > 20 {
        return false;
    }
    BLOCKED_TCP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    false
}
use retina_core::subscription::{Trackable, Subscribable};
use retina_core::conntrack::{TrackedActions, ConnInfo};
use retina_core::protocols::stream::ParserRegistry;
use retina_core::StateTransition;
use retina_core::subscription::*;
use retina_datatypes::*;
pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}
pub struct TrackedWrapper {
    packets: Vec<retina_core::Mbuf>,
    core_id: retina_core::CoreId,
    firstpayloadpkt: FirstPayloadPkt,
    exempt: retina_core::subscription::callback::StatelessCallbackWrapper,
}
impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(first_pkt: &retina_core::L4Pdu, core_id: retina_core::CoreId) -> Self {
        Self {
            packets: Vec::new(),
            core_id,
            firstpayloadpkt: FirstPayloadPkt::new(first_pkt),
            exempt: retina_core::subscription::callback::StatelessCallbackWrapper::new(
                first_pkt,
            ),
        }
    }
    fn packets(&self) -> &Vec<retina_core::Mbuf> {
        &self.packets
    }
    fn core_id(&self) -> &retina_core::CoreId {
        &self.core_id
    }
    fn parsers() -> ParserRegistry {
        ParserRegistry::from_strings(Vec::from(["http", "tls"]))
    }
    fn clear(&mut self) {
        self.packets.clear();
    }
}
pub fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {
    fn packet_filter(mbuf: &retina_core::Mbuf, core_id: &retina_core::CoreId) -> bool {
        if let Ok(ethernet)
            = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ethernet::Ethernet,
            >(mbuf) {
            if let Ok(ipv4)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv4::Ipv4,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv4) {
                    return true;
                }
            } else if let Ok(ipv6)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv6::Ipv6,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv6) {
                    return true;
                }
            }
            return false;
        }
        false
    }
    fn state_tx(conn: &mut ConnInfo<TrackedWrapper>, tx: &retina_core::StateTransition) {
        match tx {
            StateTransition::L4FirstPacket => tx_l4firstpacket(conn, &tx),
            StateTransition::L4InPayload(_) => tx_l4inpayload(conn, &tx),
            _ => {}
        }
    }
    fn tx_l4firstpacket(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = retina_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = retina_core::conntrack::TrackedActions::new();
        let mut layer0_actions = retina_core::conntrack::TrackedActions::new();
        if let Ok(ipv4)
            = &retina_core::protocols::stream::ConnData::parse_to::<
                retina_core::protocols::stream::conn::Ipv4CData,
            >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: retina_core::conntrack::Actions::from(5),
                        refresh_at: [
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(5),
                            retina_core::conntrack::Actions::from(4),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                        ],
                    },
                );
            layer0_actions
                .extend(
                    &TrackedActions {
                        active: retina_core::conntrack::Actions::from(2),
                        refresh_at: [
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(2),
                            retina_core::conntrack::Actions::from(2),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                        ],
                    },
                );
        } else if let Ok(ipv6)
            = &retina_core::protocols::stream::ConnData::parse_to::<
                retina_core::protocols::stream::conn::Ipv6CData,
            >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: retina_core::conntrack::Actions::from(5),
                        refresh_at: [
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(5),
                            retina_core::conntrack::Actions::from(4),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                        ],
                    },
                );
            layer0_actions
                .extend(
                    &TrackedActions {
                        active: retina_core::conntrack::Actions::from(2),
                        refresh_at: [
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(2),
                            retina_core::conntrack::Actions::from(2),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                        ],
                    },
                );
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn tx_l4inpayload(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = retina_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = retina_core::conntrack::TrackedActions::new();
        let mut layer0_actions = retina_core::conntrack::TrackedActions::new();
        transport_actions
            .extend(
                &TrackedActions {
                    active: retina_core::conntrack::Actions::from(1),
                    refresh_at: [
                        retina_core::conntrack::Actions::from(0),
                        retina_core::conntrack::Actions::from(0),
                        retina_core::conntrack::Actions::from(1),
                        retina_core::conntrack::Actions::from(0),
                        retina_core::conntrack::Actions::from(0),
                        retina_core::conntrack::Actions::from(0),
                        retina_core::conntrack::Actions::from(0),
                        retina_core::conntrack::Actions::from(0),
                        retina_core::conntrack::Actions::from(0),
                    ],
                },
            );
        if conn.layers[0].layer_info().state
            == retina_core::conntrack::LayerState::Discovery
        {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: retina_core::conntrack::Actions::from(4),
                        refresh_at: [
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(4),
                            retina_core::conntrack::Actions::from(4),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                        ],
                    },
                );
            layer0_actions
                .extend(
                    &TrackedActions {
                        active: retina_core::conntrack::Actions::from(2),
                        refresh_at: [
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(2),
                            retina_core::conntrack::Actions::from(2),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                            retina_core::conntrack::Actions::from(0),
                        ],
                    },
                );
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn update(
        conn: &mut ConnInfo<TrackedWrapper>,
        pdu: &retina_core::L4Pdu,
        state: retina_core::StateTransition,
    ) -> bool {
        let mut ret = false;
        match state {
            StateTransition::L4InPayload(_) => {
                conn.tracked.firstpayloadpkt.update(pdu);
                if conn.tracked.exempt.is_active() {
                    if !exempt(
                        &conn.tracked.firstpayloadpkt,
                        &conn.layers[0].last_protocol(),
                    ) {
                        conn.tracked.exempt.set_inactive();
                        ret = true;
                    }
                }
            }
            _ => {}
        }
        ret
    }
    retina_core::filter::FilterFactory::new(
        "((ipv4) and (tcp)) or ((ipv6) and (tcp))",
        packet_filter,
        state_tx,
        update,
    )
}
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    let total = TOTAL_TCP.load(std::sync::atomic::Ordering::Relaxed);
    let blocked = BLOCKED_TCP.load(std::sync::atomic::Ordering::Relaxed);
    {
        ::std::io::_print(
            format_args!(
                "Total TCP conns: {0}, Blocked TCP conns: {1} ({2:.4}% blocked)\n",
                total,
                blocked,
                (blocked as f64 / total as f64) * 100.0,
            ),
        );
    };
}
