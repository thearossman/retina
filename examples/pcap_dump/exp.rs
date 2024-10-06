Filter: tls or quic or http or dns, Datatypes: ["ZcFrame"], Callback: "no_op"
Expecting 1 subsctription(s)
Tree Pkt (pass)
,`- 0: ethernet
   |- 1: ipv4
   |  |- 2: tcp -- A: Actions { data: ActionData[PacketContinue], terminal_actions: ActionData[] }
   |  `- 3: udp -- A: Actions { data: ActionData[PacketContinue], terminal_actions: ActionData[] } x
   `- 4: ipv6 x
      |- 5: tcp -- A: Actions { data: ActionData[PacketContinue], terminal_actions: ActionData[] }
      `- 6: udp -- A: Actions { data: ActionData[PacketContinue], terminal_actions: ActionData[] } x

Tree Pkt
,`- 0: ethernet
   |- 1: ipv4
   |  |- 2: tcp -- A: Actions { data: ActionData[ProtoFilter, PacketTrack], terminal_actions: ActionData[] }
   |  `- 3: udp -- A: Actions { data: ActionData[ProtoFilter, PacketTrack], terminal_actions: ActionData[] } x
   `- 4: ipv6 x
      |- 5: tcp -- A: Actions { data: ActionData[ProtoFilter, PacketTrack], terminal_actions: ActionData[] }
      `- 6: udp -- A: Actions { data: ActionData[ProtoFilter, PacketTrack], terminal_actions: ActionData[] } x

Tree Proto
,`- 0: ethernet
   |- 1: tcp
   |  |- 2: dns -- A: Actions { data: ActionData[PacketDeliver], terminal_actions: ActionData[PacketDeliver] } D: ( no_op(ZcFrame), )
   |  |- 3: http -- A: Actions { data: ActionData[PacketDeliver], terminal_actions: ActionData[PacketDeliver] } D: ( no_op(ZcFrame), ) x
   |  `- 4: tls -- A: Actions { data: ActionData[PacketDeliver], terminal_actions: ActionData[PacketDeliver] } D: ( no_op(ZcFrame), ) x
   `- 5: udp x
      |- 6: dns -- A: Actions { data: ActionData[PacketDeliver], terminal_actions: ActionData[PacketDeliver] } D: ( no_op(ZcFrame), )
      `- 7: quic -- A: Actions { data: ActionData[PacketDeliver], terminal_actions: ActionData[PacketDeliver] } D: ( no_op(ZcFrame), ) x

Tree S
,`- 0: ethernet

Tree C (D)
,`- 0: ethernet

Tree Pkt (D)
,`- 0: ethernet D: ( no_op(ZcFrame), )

Datatypes {
  ZcFrame,
}

Parsers {
  tls,
  dns,
  http,
  quic,
}

#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use retina_core::config::load_config;
use retina_core::{CoreId, Runtime, FiveTuple};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use retina_core::protocols::stream::SessionData;
use retina_core::protocols::packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL};
use std::io::Write;
use std::sync::atomic::{Ordering, AtomicPtr};
use std::time::Duration;
use std::net::SocketAddr::{V4, V6};
use array_init::array_init;
use clap::Parser;
use lazy_static::lazy_static;
use std::path::PathBuf;
use serde::Serialize;
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "pcap_dump.pcap"
    )]
    outfile: PathBuf,
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
        let __clap_app = clap::Command::new("pcap_dump");
        <Self as clap::Args>::augment_args(__clap_app)
    }
    fn into_app_for_update<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("pcap_dump");
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
            config: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        );
                        res
                    },
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?,
            outfile: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("outfile")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "outfile",
                            ),
                        );
                        res
                    },
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
        if __clap_arg_matches.contains_id("config") {
            #[allow(non_snake_case)]
            let config = &mut self.config;
            *config = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        );
                        res
                    },
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?;
        }
        if __clap_arg_matches.contains_id("outfile") {
            #[allow(non_snake_case)]
            let outfile = &mut self.outfile;
            *outfile = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("outfile")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "outfile",
                            ),
                        );
                        res
                    },
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
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(true && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg.short('c').long("config").value_name("FILE");
                    arg
                });
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
                        .default_value("pcap_dump.pcap");
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
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg.short('c').long("config").value_name("FILE");
                    arg
                });
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
                        .default_value("pcap_dump.pcap");
                    arg
                });
            __clap_app
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for Args {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "Args",
            "config",
            &self.config,
            "outfile",
            &&self.outfile,
        )
    }
}
fn no_op(zcfame: &ZcFrame) {}
use retina_core::filter::actions::*;
use retina_core::subscription::{Trackable, Subscribable};
pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}
pub struct TrackedWrapper {
    sessions: Vec<retina_core::protocols::Session>,
    mbufs: Vec<retina_core::Mbuf>,
    core_id: retina_core::CoreId,
}
impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(pdu: &retina_core::L4Pdu, core_id: retina_core::CoreId) -> Self {
        Self {
            sessions: ::alloc::vec::Vec::new(),
            mbufs: ::alloc::vec::Vec::new(),
            core_id,
        }
    }
    fn update(&mut self, pdu: &retina_core::L4Pdu, reassembled: bool) {}
    fn core_id(&self) -> &retina_core::CoreId {
        &self.core_id
    }
    fn track_packet(&mut self, mbuf: retina_core::Mbuf) {
        self.mbufs.push(mbuf);
    }
    fn packets(&self) -> &Vec<retina_core::Mbuf> {
        &self.mbufs
    }
    fn drain_packets(&mut self) {
        self.mbufs = ::alloc::vec::Vec::new();
    }
    fn clear(&mut self) {
        self.drain_packets();
        self.sessions = ::alloc::vec::Vec::new();
    }
    fn sessions(&self) -> &Vec<retina_core::protocols::Session> {
        &self.sessions
    }
    fn track_session(&mut self, session: retina_core::protocols::Session) {
        self.sessions.push(session);
    }
    fn parsers() -> retina_core::protocols::stream::ParserRegistry {
        retina_core::protocols::stream::ParserRegistry::from_strings(
            <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new(["tls", "dns", "http", "quic"]),
            ),
        )
    }
}
pub fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {
    fn packet_continue(
        mbuf: &retina_core::Mbuf,
        core_id: &retina_core::CoreId,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        if let Ok(ethernet) = &retina_core::protocols::packet::Packet::parse_to::<
            retina_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv4) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv4) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            } else if let Ok(ipv6) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv6) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            }
        }
        result
    }
    fn packet_filter(mbuf: &retina_core::Mbuf) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        if let Ok(ethernet) = &retina_core::protocols::packet::Packet::parse_to::<
            retina_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv4) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(520),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv4) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(520),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            } else if let Ok(ipv6) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(520),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv6) {
                    result
                        .add_actions(
                            &Actions {
                                data: ActionData::from(520),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            }
        }
        result
    }
    fn protocol_filter(
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        if let Ok(tcp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::TcpCData,
        >(conn) {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Dns { .. } => true,
                _ => false,
            } {
                result
                    .add_actions(
                        &Actions {
                            data: ActionData::from(2),
                            terminal_actions: ActionData::from(2),
                        },
                    );
                for mbuf in tracked.packets() {
                    if let Some(p) = ZcFrame::from_mbuf(mbuf) {
                        no_op(p);
                    }
                }
            } else if match conn.service() {
                retina_core::protocols::stream::ConnParser::Http { .. } => true,
                _ => false,
            } {
                result
                    .add_actions(
                        &Actions {
                            data: ActionData::from(2),
                            terminal_actions: ActionData::from(2),
                        },
                    );
                for mbuf in tracked.packets() {
                    if let Some(p) = ZcFrame::from_mbuf(mbuf) {
                        no_op(p);
                    }
                }
            } else if match conn.service() {
                retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                _ => false,
            } {
                result
                    .add_actions(
                        &Actions {
                            data: ActionData::from(2),
                            terminal_actions: ActionData::from(2),
                        },
                    );
                for mbuf in tracked.packets() {
                    if let Some(p) = ZcFrame::from_mbuf(mbuf) {
                        no_op(p);
                    }
                }
            }
        } else if let Ok(udp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::UdpCData,
        >(conn) {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Dns { .. } => true,
                _ => false,
            } {
                result
                    .add_actions(
                        &Actions {
                            data: ActionData::from(2),
                            terminal_actions: ActionData::from(2),
                        },
                    );
                for mbuf in tracked.packets() {
                    if let Some(p) = ZcFrame::from_mbuf(mbuf) {
                        no_op(p);
                    }
                }
            } else if match conn.service() {
                retina_core::protocols::stream::ConnParser::Quic { .. } => true,
                _ => false,
            } {
                result
                    .add_actions(
                        &Actions {
                            data: ActionData::from(2),
                            terminal_actions: ActionData::from(2),
                        },
                    );
                for mbuf in tracked.packets() {
                    if let Some(p) = ZcFrame::from_mbuf(mbuf) {
                        no_op(p);
                    }
                }
            }
        }
        result
    }
    fn session_filter(
        session: &retina_core::protocols::Session,
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        result
    }
    fn packet_deliver(
        mbuf: &retina_core::Mbuf,
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
    ) {
        if let Some(p) = ZcFrame::from_mbuf(mbuf) {
            no_op(p);
        }
    }
    fn connection_deliver(
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
    ) {}
    retina_core::filter::FilterFactory::new(
        "((ipv4) and (tcp)) or ((ipv4) and (udp)) or ((ipv6) and (tcp)) or ((ipv6) and (udp))",
        packet_continue,
        packet_filter,
        protocol_filter,
        session_filter,
        packet_deliver,
        connection_deliver,
    )
}
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let cores = config.get_all_rx_core_ids();
    let num_cores = cores.len();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
