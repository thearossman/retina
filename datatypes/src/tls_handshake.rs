//! A TLS handshake.
//! Subscribable alias for [`retina_core::protocols::stream::tls::Tls`]

use crate::FromSession;
use retina_core::protocols::stream::tls::Tls;
use retina_core::protocols::stream::{Session, SessionData};
#[allow(unused_imports)]
use retina_filtergen::{datatype, datatype_group};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs"))]
pub type TlsHandshake = Box<Tls>;

impl FromSession for TlsHandshake {
    fn stream_protocols() -> Vec<&'static str> {
        vec!["tls"]
    }

    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("TlsHandshake,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Tls(tls) = &session.data {
            return Some(tls);
        }
        None
    }
}
