//! A DNS transaction.
//! Subscribable alias for [`retina_core::protocols::stream::dns::Dns`]

use crate::FromSession;
use retina_core::protocols::stream::dns::Dns;
use retina_core::protocols::stream::{Session, SessionData};
#[allow(unused_imports)]
use retina_filtergen::{datatype, datatype_group};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=dns"))]
pub type DnsTransaction = Box<Dns>;

impl FromSession for DnsTransaction {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("DnsTransaction,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Dns(dns) = &session.data {
            return Some(dns);
        }
        None
    }
}
