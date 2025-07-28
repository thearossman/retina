//! A TLS handshake.
//! Subscribable alias for [`retina_core::protocols::stream::tls::Tls`]

use retina_core::protocols::stream::tls::Tls;
use retina_core::protocols::stream::{Session, SessionData};
use retina_filtergen::{datatype, datatype_group};
use crate::FromSession;

#[datatype("L7EndHeaders")]
pub type TlsHandshake = Box<Tls>;

impl FromSession for TlsHandshake {
    fn stream_protocols() -> Vec<&'static str> {
        vec!["tls"]
    }

    #[datatype_group("TlsHandshake,level=L7EndHeaders")]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Tls(tls) = &session.data {
            return Some(tls);
        }
        None
    }
}
