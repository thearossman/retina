use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::{L4Context, L4Pdu};
use retina_core::conntrack::ConnTracker;
use retina_core::memory::mbuf::Mbuf;
use retina_core::protocols::stream::{ConnParser, Session, ConnData};
use retina_core::subscription::{Subscribable, Subscription, Trackable};
use retina_core::filter::actions::*;
use retina_datatypes::*;
use lazy_static::lazy_static;
use std::sync::RwLock;

use retina_core::protocols::stream::http::parser::HttpParser;


use retina_filtergen::subscription;

lazy_static!(
    static ref CYCLES: RwLock<u64> = RwLock::new(0);
    static ref HTTP: RwLock<u64> = RwLock::new(0);
    static ref TCP80: RwLock<u64> = RwLock::new(0);
    static ref IPDST: RwLock<u64> = RwLock::new(0);
    static ref IPSRC: RwLock<u64> = RwLock::new(0);
    static ref ETH: RwLock<u64> = RwLock::new(0);
);

#[inline]
fn http_cb(subscribed: Subscribed) {
    *HTTP.write().unwrap() += 1;
    println!("{:?}", subscribed);
}

pub(crate) fn print() {
    println!("HTTP: {}", *HTTP.read().unwrap());
}

#[subscription("/home/tcr6/retina/examples/basic/filter.toml")]
fn test() {}