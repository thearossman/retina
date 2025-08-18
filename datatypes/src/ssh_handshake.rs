//! A SSH handshake.
//! Subscribable alias for [`retina_core::protocols::stream::ssh::Ssh`]

use crate::FromSession;
use retina_core::protocols::stream::ssh::Ssh;
use retina_core::protocols::stream::{Session, SessionData};
#[allow(unused_imports)]
use retina_filtergen::{datatype, datatype_group};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=ssh"))]
pub type SshHandshake = Box<Ssh>;

impl FromSession for SshHandshake {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("SshHandshake,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Ssh(ssh) = &session.data {
            return Some(ssh);
        }
        None
    }
}
