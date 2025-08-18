//! An Http transaction.
//! Subscribable alias for [`retina_core::protocols::stream::http::Http`]

use crate::FromSession;
use retina_core::protocols::stream::http::Http;
use retina_core::protocols::stream::{Session, SessionData};
#[allow(unused_imports)]
use retina_filtergen::{datatype, datatype_group};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=http"))]
pub type HttpTransaction = Box<Http>;

impl FromSession for HttpTransaction {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("HttpTransaction,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Http(http) = &session.data {
            return Some(http);
        }
        None
    }
}
