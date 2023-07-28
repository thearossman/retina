pub mod custom_application;
pub mod custom_connection;
pub mod custom_frame;

#[allow(unused_imports)]
use self::custom_frame::*;
#[allow(unused_imports)]
use self::custom_connection::*;
#[allow(unused_imports)]
use self::custom_application::*;

use crate::conntrack::ConnTracker;
use crate::conntrack::conn_id::{FiveTuple};
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};
use crate::conntrack::pdu::{L4Context, L4Pdu};

#[derive(Debug)]
pub struct CustomSubscribable {
    #[cfg(subscribed="frame")]
    pub frames: Vec<FrameData>,
    #[cfg(subscribed="connection")]
    pub connections: Vec<ConnectionData>,
    #[cfg(subscribed="application")]
    pub application: Option<ApplicationData>,
}

impl Subscribable for CustomSubscribable {
    type Tracked = CustomTracked; 

    fn level() -> Level {
        cfg_if::cfg_if! {
            if #[cfg(subscribed="application")] {
                Level::Session
            } else if #[cfg(subscribed="connection")] {
                Level::Connection
            } else {
                Level::Packet
            }
        }
    }

    fn parsers() -> Vec<ConnParser> {
        cfg_if::cfg_if! {
            if #[cfg(subscribed="application")] {
                custom_parsers()
            } else {
                vec![]
            }
        }
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        match subscription.filter_packet(&mbuf) {
            FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                if let Ok(ctxt) = L4Context::new(&mbuf, idx) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
            FilterResult::NoMatch => drop(mbuf),
        }
    }
}

#[allow(dead_code)]
pub struct CustomTracked {
    frames: Option<FrameTracker>,
    connections: Option<ConnectionTracker>,
    application: Option<ApplicationTracker>,
}

impl Trackable for CustomTracked {
    type Subscribed = CustomSubscribable;

    fn new(_five_tuple: FiveTuple) -> Self {
        #[allow(unused_mut, unused_assignments)]
        let (mut frames, 
            mut connections, 
            mut application) = ( None, None, None );

        #[cfg(subscribed="frame")] { frames = Some(FrameTracker::new()); }
        #[cfg(subscribed="connection")] { connections = Some(ConnectionTracker::new(_five_tuple)); }
        #[cfg(subscribed="application")] { application = Some(ApplicationTracker::new()); }

        CustomTracked {
            frames: frames, 
            connections: connections,
            application: application
        }
    }

    fn pre_match(&mut self, _pdu: L4Pdu, _session_id: Option<usize>) {
        #[cfg(subscribed="connection")]
        if let Some(connections) = &mut self.connections { connections.pre_match(&_pdu, _session_id) };
        #[cfg(subscribed="frame")]
        if let Some(frames) = &mut self.frames { frames.pre_match(_pdu, _session_id) };
    }

    // Built out of tracked pieces
    fn on_match(&mut self, _session: Session, _subscription: &Subscription<Self::Subscribed>) {
        /* 
         * TODO: deliver packets then decide whether to stop tracking or not?

         * - If only delivering packets, deliver them
         * - If only delivering application data that is done when matched (eg HTTP, DNS), deliver
         # - If delivering app data that parser will discard on match, store it
         */
        #[cfg(subscribed="connection")]
        if let Some(connections) = &mut self.connections { connections.on_match(&_session) }; // should return value here re: whether to track
        #[cfg(subscribed="frame")]
        if let Some(frames) = &mut self.frames { frames.on_match(&_session) }; 
        #[cfg(subscribed="application")]
        if let Some(application) = &mut self.application { application.on_match(_session); }
    }

    fn post_match(&mut self, _pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {
        /* 
         * - If only delivering packets, deliver them
         * - If tracking connection data, update it
         */
        #[cfg(subscribed="connection")]
        if let Some(connections) = &mut self.connections { connections.post_match(&_pdu) };
        #[cfg(subscribed="frame")]
        if let Some(frames) = &mut self.frames { frames.post_match(_pdu) };
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        /* 
         * - If tracking connection data, deliver everything
         */
        #[cfg(subscribed="connection")]
        if let Some(connections) = &mut self.connections { connections.on_terminate() };
        #[cfg(subscribed="frame")]
        if let Some(frames) = &mut self.frames { frames.on_terminate() };

        #[cfg(subscribed="frame")]
        let _frames = std::mem::replace(&mut self.frames, None);
        #[cfg(subscribed="connection")]
        let _connections = std::mem::replace(&mut self.connections, None);
        #[cfg(subscribed="application")]
        let _application = std::mem::replace(&mut self.application, None);

        // tmp - figure out lifetimes
        // TODO 
        let ret = CustomSubscribable {
            #[cfg(subscribed="frame")]
            frames: _frames.unwrap().to_data(),
            #[cfg(subscribed="connection")]
            connections: _connections.unwrap().to_data(),
            #[cfg(subscribed="application")]
            application: _application.unwrap().to_data(),
        };

        subscription.invoke(ret);
    }
    
}