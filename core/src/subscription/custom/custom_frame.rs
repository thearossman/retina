use std::collections::HashMap;
use crate::memory::mbuf::Mbuf;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{Session};

#[allow(unused_imports)]
use crate::subscription::{frame::Frame, zc_frame::ZcFrame};

#[derive(Debug)]
pub struct FrameData {
    #[cfg(frame="frame")]
    pub frame: Frame,
    #[cfg(frame="zc_frame")]
    pub zc_frame: Mbuf,
}


#[allow(dead_code)]
pub(super) struct FrameTracker {
    session_buf: HashMap<usize, Vec<Mbuf>>,
    pub matched_session: Vec<Mbuf>,
}

#[allow(dead_code)]
impl FrameTracker {

    pub fn new() -> Self {
        FrameTracker {
            session_buf: HashMap::new(),
            matched_session: Vec::new(),
        }
    }

    pub fn pre_match(&mut self, pdu: L4Pdu, session_id: Option<usize>) {
        if let Some(session_id) = session_id {
            self.session_buf
                .entry(session_id)
                .or_insert_with(Vec::new)
                .push(pdu.mbuf_own());
        } else {
            drop(pdu);
        }
    }

    pub fn on_match(&mut self, session: &Session) { 
        if let Some(data) = self.session_buf.remove(&session.id) {
            self.matched_session = data;
        }   
    }

    pub fn post_match(&mut self, pdu: L4Pdu) { 
        self.matched_session.push(pdu.mbuf_own());
    }

    pub fn on_terminate(&mut self) { }

    pub fn to_data(self) -> Vec<FrameData> {
        let mut ret = vec![];

        if !self.matched_session.is_empty() {    
            self.matched_session.into_iter().for_each(|mbuf| {
                ret.push(FrameData::new(mbuf));
            });
        }
        ret
    }
}

impl FrameData {
    pub fn new(_mbuf: Mbuf) -> Self {
        FrameData {
            #[cfg(frame="frame")]
            frame: Frame::from_mbuf(&_mbuf),
            #[cfg(frame="zc_frame")]
            zc_frame: _mbuf,
        }
    }
}