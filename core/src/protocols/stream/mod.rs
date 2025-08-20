//! Types for parsing and manipulating stream-level network protocols.
//!
//! Any protocol that requires parsing over multiple packets within a single connection or flow is
//! considered a "stream-level" protocol, even if it is a datagram-based protocol in the
//! traditional-sense.

#[doc(hidden)]
pub mod conn;
pub mod dns;
pub mod http;
pub mod quic;
pub mod ssh;
pub mod tls;

use self::conn::ConnField;
use self::conn::{Ipv4CData, Ipv6CData, TcpCData, UdpCData};
use self::dns::{parser::DnsParser, Dns};
use self::http::{parser::HttpParser, Http};
use self::quic::parser::QuicParser;
use self::ssh::{parser::SshParser, Ssh};
use self::tls::{parser::TlsParser, Tls};
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;

use std::collections::HashSet;
use std::str::FromStr;

use anyhow::Result;
use quic::QuicConn;
use strum_macros::EnumString;

pub const IMPLEMENTED_PROTOCOLS: [&str; 5] = ["tls", "dns", "http", "quic", "ssh"];

/// Represents the result of parsing one packet as a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseResult {
    /// Session headers done, ready to be filtered on.
    /// Returns the most-recently-updated session ID.
    HeadersDone(usize),
    /// Session parsing, including body, done. Returns the most-recently-updated session ID.
    Done(usize),
    /// Successfully extracted data, continue processing more packets. Returns most recently updated
    /// session ID.
    Continue(usize),
    /// Parsing skipped, no data extracted.
    Skipped,
    /// For Unknown parser
    None,
}

/// Represents the result of a probing one packet as a protocol message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeResult {
    /// Segment matches the parser with great probability.
    Certain,
    /// Unsure if the segment matches the parser.
    Unsure,
    /// Segment does not match the parser.
    NotForUs,
    /// Error occurred during the probe. Functionally equivalent to Unsure.
    Error,
}

/// Represents the result of probing one packet with all registered protocol parsers.
#[derive(Debug)]
pub(crate) enum ProbeRegistryResult {
    /// A parser in the registry was definitively matched.
    Some(ConnParser),
    /// All parsers in the registry were definitively not matched.
    None,
    /// Unsure, continue sending more data.
    Unsure,
}

/// The set of application-layer protocol parsers required to fulfill the subscription.
#[derive(Debug)]
pub struct ParserRegistry(Vec<ConnParser>);

impl ParserRegistry {
    // Assumes that `input` is deduplicated
    pub fn from_strings(input: Vec<&'static str>) -> ParserRegistry {
        // Deduplicate
        let stream_protocols: HashSet<&'static str> = input.into_iter().collect();
        let mut parsers = vec![];
        for stream_protocol in stream_protocols {
            let parser = ConnParser::from_str(stream_protocol)
                .unwrap_or_else(|_| panic!("Invalid stream protocol: {}", stream_protocol));
            parsers.push(parser);
        }
        ParserRegistry(parsers)
    }

    /// Probe the packet `pdu` with all registered protocol parsers.
    pub(crate) fn probe_all(&self, pdu: &L4Pdu) -> ProbeRegistryResult {
        if self.0.is_empty() {
            return ProbeRegistryResult::None;
        }
        if pdu.length() == 0 {
            return ProbeRegistryResult::Unsure;
        }

        let mut num_notmatched = 0;
        for parser in self.0.iter() {
            match parser.probe(pdu) {
                ProbeResult::Certain => {
                    return ProbeRegistryResult::Some(parser.reset_new());
                }
                ProbeResult::NotForUs => {
                    num_notmatched += 1;
                }
                _ => (), // Unsure, Error, Reverse
            }
        }
        if num_notmatched == self.0.len() {
            ProbeRegistryResult::None
        } else {
            ProbeRegistryResult::Unsure
        }
    }
}

/// A trait all application-layer protocol parsers must implement.
pub(crate) trait ConnParsable {
    /// Parse the L4 protocol data unit as the parser's protocol.
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult;

    /// Probe if the L4 protocol data unit matches the parser's protocol.
    fn probe(&self, pdu: &L4Pdu) -> ProbeResult;

    /// Removes session with ID `session_id` and returns it.
    fn remove_session(&mut self, session_id: usize) -> Option<Session>;

    /// Removes all sessions in the connection parser and returns them.
    fn drain_sessions(&mut self) -> Vec<Session>;

    /// Indicates whether we expect to see >1 sessions per connection
    fn session_parsed_state(&self) -> ParsingState;

    /// If applicable, returns the offset into the most recently processed payload
    /// where application-layer body begins. Some and non-zero if a payload contains
    /// both header and body data. Clears the offset after access.
    fn body_offset(&mut self) -> Option<usize>;
}

/// Data required to filter on Five-Tuple fields after the first packet.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug)]
pub struct ConnData {
    /// The connection 5-tuple.
    pub five_tuple: FiveTuple,
}

// TODO get rid of ConnData - likely no longer needed
impl ConnData {
    pub(crate) fn supported_fields() -> Vec<&'static str> {
        let mut v: Vec<_> = TcpCData::supported_fields()
            .into_iter()
            .chain(UdpCData::supported_fields())
            .chain(Ipv4CData::supported_fields())
            .chain(Ipv6CData::supported_fields())
            .collect();
        v.dedup();
        v
    }

    pub(crate) fn supported_protocols() -> Vec<&'static str> {
        vec!["ipv4", "ipv6", "tcp", "udp"]
    }

    /// Create a new `ConnData` from the connection `five_tuple` and the ID of the last matched node
    /// in the filter predicate trie.
    pub(crate) fn new(five_tuple: FiveTuple) -> Self {
        ConnData { five_tuple }
    }

    /// Parses the `ConnData`'s FiveTuple into sub-protocol metadata
    pub fn parse_to<T: ConnField>(&self) -> Result<T>
    where
        Self: Sized,
    {
        T::parse_from(self)
    }
}

/// Data required to filter on application-layer protocol sessions.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug)]
pub enum SessionData {
    // TODO: refactor to use trait objects.
    Tls(Box<Tls>),
    Dns(Box<Dns>),
    Http(Box<Http>),
    Quic(Box<QuicConn>),
    Ssh(Box<Ssh>),
    Null,
}

/// Supported session (encapsulated in L4 connection)
/// Includes possibility for nested protocols
#[derive(Debug, Clone)]
pub enum SessionProto {
    Tls,
    Dns,
    Http,
    Quic,
    Ssh,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Null,    // All protocol identification has failed
    Probing, // Protocol identification ongoing
}

/// An application-layer protocol session.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug)]
pub struct Session {
    /// Application-layer session data.
    pub data: SessionData,
    /// A unique identifier that represents the arrival order of the first packet of the session.
    pub id: usize,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            data: SessionData::Null,
            id: 0,
        }
    }
}

/// A connection protocol parser.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnParser {
    // TODO: refactor to use trait objects.
    Tls(TlsParser),
    Dns(DnsParser),
    Http(HttpParser),
    Quic(QuicParser),
    Ssh(SshParser),
    Unknown,
}

impl ConnParser {
    /// Returns a new connection protocol parser of the same type, but with state reset.
    pub(crate) fn reset_new(&self) -> ConnParser {
        match self {
            ConnParser::Tls(_) => ConnParser::Tls(TlsParser::default()),
            ConnParser::Dns(_) => ConnParser::Dns(DnsParser::default()),
            ConnParser::Http(_) => ConnParser::Http(HttpParser::default()),
            ConnParser::Quic(_) => ConnParser::Quic(QuicParser::default()),
            ConnParser::Ssh(_) => ConnParser::Ssh(SshParser::default()),
            ConnParser::Unknown => ConnParser::Unknown,
        }
    }

    /// Returns the result of parsing `pdu` as a protocol message.
    pub(crate) fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        match self {
            ConnParser::Tls(parser) => parser.parse(pdu),
            ConnParser::Dns(parser) => parser.parse(pdu),
            ConnParser::Http(parser) => parser.parse(pdu),
            ConnParser::Quic(parser) => parser.parse(pdu),
            ConnParser::Ssh(parser) => parser.parse(pdu),
            ConnParser::Unknown => ParseResult::None,
        }
    }

    /// Returns the result of probing whether `pdu` is a protocol message.
    pub(crate) fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        match self {
            ConnParser::Tls(parser) => parser.probe(pdu),
            ConnParser::Dns(parser) => parser.probe(pdu),
            ConnParser::Http(parser) => parser.probe(pdu),
            ConnParser::Quic(parser) => parser.probe(pdu),
            ConnParser::Ssh(parser) => parser.probe(pdu),
            ConnParser::Unknown => ProbeResult::Error,
        }
    }

    /// Removes the session with ID `session_id` from any protocol state managed by the parser, and
    /// returns it.
    pub(crate) fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        match self {
            ConnParser::Tls(parser) => parser.remove_session(session_id),
            ConnParser::Dns(parser) => parser.remove_session(session_id),
            ConnParser::Http(parser) => parser.remove_session(session_id),
            ConnParser::Quic(parser) => parser.remove_session(session_id),
            ConnParser::Ssh(parser) => parser.remove_session(session_id),
            ConnParser::Unknown => None,
        }
    }

    /// Removes all remaining sessions managed by the parser and returns them.
    pub(crate) fn drain_sessions(&mut self) -> Vec<Session> {
        match self {
            ConnParser::Tls(parser) => parser.drain_sessions(),
            ConnParser::Dns(parser) => parser.drain_sessions(),
            ConnParser::Http(parser) => parser.drain_sessions(),
            ConnParser::Quic(parser) => parser.drain_sessions(),
            ConnParser::Ssh(parser) => parser.drain_sessions(),
            ConnParser::Unknown => vec![],
        }
    }

    pub(crate) fn session_parsed_state(&self) -> ParsingState {
        match self {
            ConnParser::Tls(parser) => parser.session_parsed_state(),
            ConnParser::Dns(parser) => parser.session_parsed_state(),
            ConnParser::Http(parser) => parser.session_parsed_state(),
            ConnParser::Quic(parser) => parser.session_parsed_state(),
            ConnParser::Ssh(parser) => parser.session_parsed_state(),
            ConnParser::Unknown => ParsingState::Stop,
        }
    }

    pub(crate) fn body_offset(&mut self) -> Option<usize> {
        match self {
            ConnParser::Tls(parser) => parser.body_offset(),
            ConnParser::Dns(parser) => parser.body_offset(),
            ConnParser::Http(parser) => parser.body_offset(),
            ConnParser::Quic(parser) => parser.body_offset(),
            ConnParser::Ssh(parser) => parser.body_offset(),
            ConnParser::Unknown => None,
        }
    }

    // \note This should match the name of the protocol used
    // in the filter syntax (see filter/ast.rs::LAYERS)
    pub fn protocol_name(&self) -> Option<String> {
        match self {
            ConnParser::Tls(_parser) => Some("tls".into()),
            ConnParser::Dns(_parser) => Some("dns".into()),
            ConnParser::Http(_parser) => Some("http".into()),
            ConnParser::Quic(_parser) => Some("quic".into()),
            ConnParser::Ssh(_parser) => Some("ssh".into()),
            ConnParser::Unknown => None,
        }
    }

    pub fn protocol(&self) -> SessionProto {
        match self {
            ConnParser::Tls(_) => SessionProto::Tls,
            ConnParser::Dns(_) => SessionProto::Dns,
            ConnParser::Http(_) => SessionProto::Http,
            ConnParser::Quic(_) => SessionProto::Quic,
            ConnParser::Ssh(_) => SessionProto::Ssh,
            ConnParser::Unknown => SessionProto::Null,
        }
    }

    pub fn requires_parsing(filter_str: &str) -> HashSet<&'static str> {
        let mut out = hashset! {};

        for s in IMPLEMENTED_PROTOCOLS {
            if filter_str.contains(s) {
                out.insert(s);
            }
        }
        out
    }
}

#[derive(Debug)]
pub enum ParsingState {
    /// Unknown application-layer protocol, needs probing.
    Probing,
    /// Known application-layer protocol, needs parsing.
    Parsing,
    /// No more sessions expected in connection.
    Stop,
}
