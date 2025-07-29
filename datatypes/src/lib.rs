//!
//! Subscribable data types.
//!
//! A subscription is a request for a callback on a subset of network traffic specified by a filter.
//! Each callback function requires one or more *subscribable data types* as parameter(s), which it
//! immutably borrows.
//!
//! Each subscribable datatype must:
//!
//! - Be defined as a [DataType](retina_core::filter::DataType), with appropriate parameters and [retina_core::filter::Level].
//! - Implement one of the traits defined in this module (Tracked, FromSession, etc.)
//! - Be added to the [DATATYPES](`crate::typedefs::DATATYPES`) map (note: we are actively working on an approach that eliminates this requirement).
//!
//!

use retina_core::{L4Pdu, Mbuf, protocols::Session};
pub mod conn_fts;
pub mod tls_handshake;
use retina_filtergen::cache_file;
pub use tls_handshake::TlsHandshake;
pub mod static_type;
pub use static_type::*;
// pub mod typedefs;
// pub use conn_fts::*;
pub mod connection;
pub use connection::ConnRecord;
// pub mod http_transaction;
// pub use http_transaction::HttpTransaction;
// pub mod dns_transaction;
// pub use dns_transaction::DnsTransaction;
// pub mod quic_stream;
// pub use quic_stream::QuicStream;
// pub mod ssh_handshake;
// pub use ssh_handshake::SshHandshake;
// pub mod packet;
// pub use packet::{Payload, ZcFrame};
// pub mod packet_list;
// pub use packet_list::*;
// pub use typedefs::*;
// pub mod streaming;

/// No-op function to invoke macro
/// TODO can we do this more cleanly?
#[cfg_attr(not(feature = "skip_expand"),
    cache_file("$RETINA_HOME/datatypes/data.jsonl"))]
fn _cache_file() {}

/// Need to define traits in this crate to avoid
/// "cannot define inherent `impl` for foreign type" and
/// "only traits defined in the current crate can be implemented
/// for types defined outside of the crate" errors.
/// Convenience method to convert a `Session` into a datatype that
/// can be subscribed to. Datatypes implementing this trait are
/// automatically Level=L7EndHdrs.
pub trait FromSession {
    /// The stream protocols (lower-case) required for this datatype.
    /// See `IMPLEMENTED_PROTOCOLS` in retina_core for list of supported protocols.
    fn stream_protocols() -> Vec<&'static str>;
    /// Build Self from a parsed session, or return None if impossible.
    /// Invoked when the session is fully matched, parsed, and ready to
    /// be delivered to a callback.
    fn new(session: &Session) -> Option<&Self>;
}

/// Convenience method to convert an `Mbuf` into a datatype that
/// can be subscribed to. Datatypes implementing this trait
/// are automatically Level=Packet.
pub trait FromMbuf {
    fn new(mbuf: &Mbuf) -> Self;
}

/// Trait implemented by datatypes that are constant throughout
/// a connection and inferrable at first packet (level is L4FirstPacket).
pub trait StaticData {
    fn new(first_pkt: &L4Pdu) -> Self;
}