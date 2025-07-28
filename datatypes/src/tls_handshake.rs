//! A TLS handshake.
//! Subscribable alias for [`retina_core::protocols::stream::tls::Tls`]

use retina_core::protocols::stream::tls::Tls;
use retina_core::protocols::stream::{Session, SessionData};
use retina_filtergen::datatype;
use crate::FromSession;

#[datatype("L7EndHdrs")]
pub type TlsHandshake = Box<Tls>;

impl FromSession for TlsHandshake {
    fn stream_protocols() -> Vec<&'static str> {
        vec!["tls"]
    }

    fn new(session: &Session) -> Option<&Self> {
        if let SessionData::Tls(tls) = &session.data {
            return Some(tls);
        }
        None
    }
}
