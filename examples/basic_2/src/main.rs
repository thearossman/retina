use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};

fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    // println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}

fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
    //println!(
    //    "DNS query domain: {}, conn. metrics: {:?}",
    //    dns.query_domain(),
    //    conn_record
    //);
}

fn npkts_cb_tcp(tracked: &TrackedWrapper, core_id: &retina_core::CoreId) -> bool {
    // println!("npkts tcp");
    true
}

fn npkts_cb_udp(tracked: &TrackedWrapper, core_id: &retina_core::CoreId) -> bool {
    // println!("npkts udp");
    true
}

fn npkts_cb_tls(tracked: &TrackedWrapper, core_id: &retina_core::CoreId) -> bool {
    // println!("npkts tls");
    true
}

fn npkts_cb_dns(tracked: &TrackedWrapper, core_id: &retina_core::CoreId) -> bool {
    // println!("npkts dns");
    true
}

use retina_core::filter::actions::*;
use retina_core::filter::*;
use retina_core::subscription::{Trackable, Subscribable};
use retina_datatypes::{FromSession, Tracked};
pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}
pub struct TrackedWrapper {
    sessions: Vec<retina_core::protocols::Session>,
    mbufs: Vec<retina_core::Mbuf>,
    core_id: retina_core::CoreId,
    connrecord: ConnRecord,
}
impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(pdu: &retina_core::L4Pdu, core_id: retina_core::CoreId) -> Self {
        Self {
            sessions: Vec::new(),
            mbufs: Vec::new(),
            core_id,
            connrecord: ConnRecord::new(pdu),
        }
    }
    fn update(&mut self, pdu: &retina_core::L4Pdu, reassembled: bool) {
        self.connrecord.update(pdu, reassembled);
    }
    fn core_id(&self) -> &retina_core::CoreId {
        &self.core_id
    }
    fn track_packet(&mut self, mbuf: retina_core::Mbuf) {
        self.mbufs.push(mbuf);
    }
    fn packets(&self) -> &Vec<retina_core::Mbuf> {
        &self.mbufs
    }
    fn drain_packets(&mut self) {
        self.mbufs = Vec::new();
    }
    fn clear(&mut self) {
        self.drain_packets();
        self.sessions = Vec::new();
        self.connrecord.clear();
    }
    fn sessions(&self) -> &Vec<retina_core::protocols::Session> {
        &self.sessions
    }
    fn track_session(&mut self, session: retina_core::protocols::Session) {
        self.sessions.push(session);
    }
    fn parsers() -> retina_core::protocols::stream::ParserRegistry {
        retina_core::protocols::stream::ParserRegistry::from_strings(
            vec!["tls", "dns"]
        )
    }
}
pub fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {
    fn packet_continue(
        mbuf: &retina_core::Mbuf,
        core_id: &retina_core::CoreId,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        if let Ok(ethernet) = &retina_core::protocols::packet::Packet::parse_to::<
            retina_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv4) {
                    result
                        .push(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv4) {
                    result
                        .push(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            } else if let Ok(ipv6) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    result
                        .push(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv6) {
                    result
                        .push(
                            &Actions {
                                data: ActionData::from(1),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            }
        }
        result
    }

    fn packet_filter(mbuf: &retina_core::Mbuf, tracked: &TrackedWrapper) -> (Actions, Vec<StreamingCbWrapper<TrackedWrapper>>) {
        let mut result = retina_core::filter::Actions::new();
        let mut dyn_cbs = vec![];
        if let Ok(ethernet) = &retina_core::protocols::packet::Packet::parse_to::<
            retina_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv4) {

                    result
                        .push(
                            &Actions {
                                data: ActionData::from(272),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv4) {
                    result
                        .push(
                            &Actions {
                                data: ActionData::from(272),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            } else if let Ok(ipv6) = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    result
                        .push(
                            &Actions {
                                data: ActionData::from(272),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                } else if let Ok(udp) = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::udp::Udp,
                >(ipv6) {
                    result
                        .push(
                            &Actions {
                                data: ActionData::from(272),
                                terminal_actions: ActionData::from(0),
                            },
                        );
                }
            }
        }
        (result, dyn_cbs)
    }
    fn protocol_filter(
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
        stream_cbs: &mut Vec<StreamingCbWrapper<TrackedWrapper>>,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        if let Ok(tcp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::TcpCData,
        >(conn) {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Dns { .. } => true,
                _ => false,
            } {
                result
                    .push(
                        &Actions {
                            data: ActionData::from(1408),
                            terminal_actions: ActionData::from(1280),
                        },
                    );
            } else if match conn.service() {
                retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                _ => false,
            } {
                result
                    .push(
                        &Actions {
                            data: ActionData::from(1408),
                            terminal_actions: ActionData::from(1280),
                        },
                    );
            }
        } else if let Ok(udp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::UdpCData,
        >(conn) {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Dns { .. } => true,
                _ => false,
            } {
                result
                    .push(
                        &Actions {
                            data: ActionData::from(1408),
                            terminal_actions: ActionData::from(1280),
                        },
                    );
            }
        }
        result
    }
    fn session_filter(
        session: &retina_core::protocols::Session,
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
    ) -> Actions {
        let mut result = retina_core::filter::Actions::new();
        result
    }
    fn packet_deliver(
        mbuf: &retina_core::Mbuf,
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
    ) {}
    fn connection_deliver(
        conn: &retina_core::protocols::ConnData,
        tracked: &TrackedWrapper,
    ) {
        if let Ok(tcp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::TcpCData,
        >(conn) {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Dns { .. } => true,
                _ => false,
            } {
                if let Some(s) = DnsTransaction::from_sessionlist(tracked.sessions()) {
                    dns_cb(s, &tracked.connrecord);
                }
            } else if match conn.service() {
                retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                _ => false,
            } {
                if let Some(s) = TlsHandshake::from_sessionlist(tracked.sessions()) {
                    tls_cb(s, &tracked.connrecord);
                }
            }
        } else if let Ok(udp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::UdpCData,
        >(conn) {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Dns { .. } => true,
                _ => false,
            } {
                if let Some(s) = DnsTransaction::from_sessionlist(tracked.sessions()) {
                    dns_cb(s, &tracked.connrecord);
                }
            }
        }
    }

    fn stream_filter(tracked: &TrackedWrapper, _stream_cbs: &mut Vec<StreamingCbWrapper<TrackedWrapper>>, npkts: usize,
                     conn: &retina_core::protocols::ConnData)
    {
        // TODO would have to figure out how to store "unsubscribe"
        if npkts % 5 == 0 {
            if let Ok(tcp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::TcpCData,
            >(conn) {
                npkts_cb_tcp(tracked, tracked.core_id());
            }
        }
        if npkts % 10 == 0 {
            if let Ok(udp) = &retina_core::protocols::stream::ConnData::parse_to::<
            retina_core::protocols::stream::conn::UdpCData,
            >(conn) {
                npkts_cb_udp(tracked, tracked.core_id());
            }
        }
        if npkts % 50 == 0 {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Dns { .. } => true,
                _ => false,
            } {
                npkts_cb_dns(tracked, tracked.core_id());
            }
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                _ => false,
            } {
                npkts_cb_tls(tracked, tracked.core_id());
            }
        }
    }

    retina_core::filter::FilterFactory::new(
        "((ipv4) and (tcp)) or ((ipv4) and (udp)) or ((ipv6) and (tcp)) or ((ipv6) and (udp))",
        packet_continue,
        packet_filter,
        protocol_filter,
        session_filter,
        packet_deliver,
        connection_deliver,
        stream_filter,
    )
}

fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
