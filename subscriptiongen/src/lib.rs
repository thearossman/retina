mod prototypes; 
mod builder; 

use builder::{MethodBuilder, read_subscriptions};

use proc_macro::TokenStream;
use quote::quote;


#[proc_macro_attribute]
pub fn num_subscriptions(_args: TokenStream, _input: TokenStream) -> TokenStream {
    read_subscriptions("/home/trossman/retina/subscription.yml").into() // tmp
}

#[proc_macro_attribute]
pub fn subscription_type(_args: TokenStream, _input: TokenStream) -> TokenStream {

    let mut cfg = MethodBuilder::new("/home/trossman/retina/subscription.yml"); // tmp
    cfg.parse();

    let def = cfg.gen_struct(); 
    let new = cfg.gen_new();
    let update = cfg.gen_update(); 
    let deliver_session_on_match = cfg.gen_deliver_session_on_match();
    let terminate = cfg.gen_terminate(); 
    let parsers = cfg.gen_parsers();
    let structs = cfg.gen_structs();
    let enum_fields = cfg.gen_enums();
    let subscriptions = cfg.gen_subscriptions();
    let drop = cfg.gen_drop();

    let match_state = cfg.match_state();

    let imports = imports();
    let subscribable_type = subscribable_type(parsers);
    let deliverables = deliverable_data(structs, enum_fields);

    let fns = quote! {
            
        #imports

        #deliverables

        #subscribable_type

        pub struct TrackedWrapper {
            match_data: MatchData,
            #( #def )*
        }

        impl Trackable for TrackedWrapper {
            type Subscribed = SubscribableWrapper;

            fn new(five_tuple: FiveTuple, result: FilterResultData) -> Self {
                Self {
                    match_data: MatchData::new(result),
                    #( #new )*
                }
            }

            fn update(&mut self, 
                _pdu: L4Pdu, 
                _session_id: Option<usize>,
                _subscription: &Subscription<Self::Subscribed>) {
                #( #update )*
            }

            fn on_terminate(&mut self, _subscription: &Subscription<Self::Subscribed>) {
                #( #terminate )*
            }

            fn deliver_session_on_match(&mut self, session: Session, subscription: &Subscription<Self::Subscribed>) -> ConnState {
                #( #deliver_session_on_match )*
                #( #subscriptions )*
                #( #drop )*
                #match_state
            }

            fn filter_packet(&mut self, pkt_filter_result: FilterResultData) {
                self.match_data.filter_packet(pkt_filter_result);
            }
            fn filter_conn(&mut self, conn: &ConnData, subscription:  &Subscription<Self::Subscribed>) -> FilterResult {
                return self.match_data.filter_conn(conn, subscription);
            }
            fn filter_session(&mut self, session: &Session, subscription: &Subscription<Self::Subscribed>) -> bool {
                return self.match_data.filter_session(session, subscription);
            }
        }
    };

    fns.into()
}

fn subscribable_type(parsers: Vec<proc_macro2::TokenStream>) -> proc_macro2::TokenStream {
    quote! {

        pub struct SubscribableWrapper;

        impl Subscribable for SubscribableWrapper {
            type Tracked = TrackedWrapper;
            type SubscribedData = Subscribed;
        
            fn parsers() -> Vec<ConnParser> {
                vec![ #( #parsers)* ]
            }
        
            fn process_packet(
                mbuf: Mbuf,
                subscription: &Subscription<Self>,
                conn_tracker: &mut ConnTracker<Self::Tracked>,
            ) {
               let result = subscription.filter_packet(&mbuf);
                if result.terminal_matches != 0 || result.nonterminal_matches != 0 {
                    if let Ok(ctxt) = L4Context::new(&mbuf) {
                        conn_tracker.process(mbuf, ctxt, subscription, result);
                    }
                } else {
                    drop(mbuf);
                }
            }
        }
    }
}


// TODOTR
fn deliverable_data(structs: Vec<proc_macro2::TokenStream>, 
                    enum_fields: Vec<proc_macro2::TokenStream>) -> proc_macro2::TokenStream {

    quote! {
        #[derive(Debug)]
        pub enum Subscribed {
            #( #enum_fields)*
        }

        #( #structs )*
    }
}

#[allow(dead_code)]
fn imports() -> proc_macro2::TokenStream {
    // TODOTR customize
    quote! {
        use std::rc::Rc;
        use crate::conntrack::conn_id::FiveTuple;
        use crate::conntrack::pdu::{L4Context, L4Pdu};
        use crate::conntrack::ConnTracker;
        use crate::filter::{FilterResult, FilterResultData};
        use crate::memory::mbuf::Mbuf;
        use crate::protocols::stream::{ConnParser, Session, SessionData, ConnData};
        use crate::conntrack::conn::conn_info::{ConnState};
        use crate::subscription::{Trackable, MatchData, Subscription, Subscribable};
        use crate::protocols::stream::tls::{parser::TlsParser, Tls};
        use crate::protocols::stream::http::{parser::HttpParser, Http};
    }
}

#[allow(dead_code)]
fn pub_imports() -> proc_macro2::TokenStream {
    quote! {
        use std::rc::Rc;
        use retina_core::conntrack::conn_id::FiveTuple;
        use retina_core::conntrack::pdu::{L4Context, L4Pdu};
        use retina_core::conntrack::ConnTracker;
        use retina_core::filter::{FilterResult, FilterResultData};
        use retina_core::memory::mbuf::Mbuf;
        use retina_core::protocols::stream::{ConnParser, Session, SessionData, ConnData};
        use retina_core::conntrack::conn::conn_info::{ConnState};
        use retina_core::subscription::{Trackable, MatchData, Subscription, Subscribable};
        use retina_core::protocols::stream::tls::{parser::TlsParser, Tls};
        use retina_core::protocols::stream::http::{parser::HttpParser, Http};
    }
}