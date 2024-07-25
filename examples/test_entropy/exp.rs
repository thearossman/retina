`- ethernet (0) 
   |- ipv4 (1) 
   |  |- tcp (2) p
   |  |  `- tls (3) c*
   |  `- udp (4) p
   |     `- quic (5) c*
   `- ipv6 (6) 
      |- tcp (7) p
      |  `- tls (8) c*
      `- udp (9) p
         `- quic (10) c*

#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use retina_core::config::load_config;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_filtergen::filter;
use clap::Parser;
use std::path::PathBuf;
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "tls.jsonl"
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
        let __clap_app = clap::Command::new("test_entropy");
        <Self as clap::Args>::augment_args(__clap_app)
    }
    fn into_app_for_update<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("test_entropy");
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
                        .default_value("tls.jsonl");
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
                        .default_value("tls.jsonl");
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
            "config",
            &self.config,
            "outfile",
            &&self.outfile,
        )
    }
}
fn filter() -> retina_core::filter::FilterFactory {
    #[inline]
    fn packet_filter(mbuf: &retina_core::Mbuf) -> retina_core::filter::FilterResult {
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
                    return retina_core::filter::FilterResult::MatchNonTerminal(2);
                } else if let Ok(udp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::udp::Udp,
                    >(ipv4) {
                    return retina_core::filter::FilterResult::MatchNonTerminal(4);
                }
            } else if let Ok(ipv6)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv6::Ipv6,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv6) {
                    return retina_core::filter::FilterResult::MatchNonTerminal(7);
                } else if let Ok(udp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::udp::Udp,
                    >(ipv6) {
                    return retina_core::filter::FilterResult::MatchNonTerminal(9);
                }
            }
        }
        return retina_core::filter::FilterResult::NoMatch;
    }
    #[inline]
    fn connection_filter(
        conn: &retina_core::protocols::stream::ConnData,
    ) -> retina_core::filter::FilterResult {
        match conn.pkt_term_node {
            2 => {
                if match conn.service() {
                    retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                    _ => false,
                } {
                    return retina_core::filter::FilterResult::MatchTerminal(3);
                }
                return retina_core::filter::FilterResult::NoMatch;
            }
            4 => {
                if match conn.service() {
                    retina_core::protocols::stream::ConnParser::Quic { .. } => true,
                    _ => false,
                } {
                    return retina_core::filter::FilterResult::MatchTerminal(5);
                }
                return retina_core::filter::FilterResult::NoMatch;
            }
            7 => {
                if match conn.service() {
                    retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                    _ => false,
                } {
                    return retina_core::filter::FilterResult::MatchTerminal(8);
                }
                return retina_core::filter::FilterResult::NoMatch;
            }
            9 => {
                if match conn.service() {
                    retina_core::protocols::stream::ConnParser::Quic { .. } => true,
                    _ => false,
                } {
                    return retina_core::filter::FilterResult::MatchTerminal(10);
                }
                return retina_core::filter::FilterResult::NoMatch;
            }
            _ => return retina_core::filter::FilterResult::NoMatch,
        }
    }
    #[inline]
    fn session_filter(
        session: &retina_core::protocols::stream::Session,
        idx: usize,
    ) -> bool {
        match idx {
            3 => return true,
            5 => return true,
            8 => return true,
            10 => return true,
            _ => return false,
        }
    }
    retina_core::filter::FilterFactory::new(
        "tls or quic",
        packet_filter,
        connection_filter,
        session_filter,
    )
}
fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let callback = |_: ConnectionFrame| {};
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();
    Ok(())
}
