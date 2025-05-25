//! SSH parser.
//!
//! Uses parsing functions from [the Rusticata SSH
//! parser] (https://github.com/rusticata/ssh-parser/blob/master/src/ssh.rs)

use super::handshake::*;
use super::Ssh;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

use ssh_parser::*;

#[derive(Debug)]
pub struct SshParser {
    sessions: Vec<Ssh>,
}

impl Default for SshParser {
    fn default() -> Self {
        SshParser {
            sessions: vec![Ssh::new()],
        }
    }
}

impl ConnParsable for SshParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        log::debug!("Updating parser ssh");
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if !self.sessions.is_empty() {
                return self.sessions[0].process(data, pdu.dir);
            }
            ParseResult::Skipped
        } else {
            log::warn!("Malformed packet on parse");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        let offset = pdu.offset();
        let length = pdu.length();

        if length < 4 {
            return ProbeResult::Unsure;
        }

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            // check if first 4 bytes match the beginning of a SSH identification string ("SSH-")
            match &data[..4] {
                b"SSH-" => ProbeResult::Certain,
                _ => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|ssh| Session {
            data: SessionData::Ssh(Box::new(ssh)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|ssh| Session {
                data: SessionData::Ssh(Box::new(ssh)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        ParsingState::Stop
    }

    fn body_offset(&mut self) -> Option<usize> {
        match self.sessions.last_mut() {
            Some(session) => std::mem::take(&mut session.last_body_offset),
            None => None,
        }
    }
}

impl Ssh {
    /// Allocate a new SSH handshake instance.
    pub(crate) fn new() -> Ssh {
        Ssh {
            client_version_exchange: None,
            server_version_exchange: None,
            key_exchange: None,
            client_dh_key_exchange: None,
            server_dh_key_exchange: None,
            client_new_keys: None,
            server_new_keys: None,
            last_body_offset: None,
        }
    }

    fn byte_to_string(&mut self, b: &[u8]) -> String {
        String::from_utf8(b.to_vec()).unwrap()
    }

    pub(crate) fn parse_version_exchange(&mut self, data: &[u8], dir: bool) {
        let ssh_identifier = b"SSH-";
        if let Some(contains_ssh_identifier) = data
            .windows(ssh_identifier.len())
            .position(|window| window == ssh_identifier)
            .map(|p| &data[p..])
        {
            match ssh_parser::parse_ssh_identification(contains_ssh_identifier) {
                Ok((_, (_, ssh_id_string))) => {
                    let version_exchange = SshVersionExchange {
                        protoversion: Some(self.byte_to_string(ssh_id_string.proto)),
                        softwareversion: Some(self.byte_to_string(ssh_id_string.software)),
                        comments: if ssh_id_string.comments.is_some() {
                            Some(self.byte_to_string(ssh_id_string.comments.unwrap()))
                        } else {
                            None
                        },
                    };

                    if dir {
                        self.client_version_exchange = Some(version_exchange);
                    } else {
                        self.server_version_exchange = Some(version_exchange);
                    }
                }
                e => log::debug!("Not a valid SSH version exchange message: {:?}", e),
            }
        }
    }

    fn bytes_to_string_vec(&mut self, data: &[u8]) -> Vec<String> {
        data.split(|&b| b == b',')
            .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
            .collect()
    }

    pub(crate) fn parse_key_exchange(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => match pkt {
                SshPacket::KeyExchange(pkt) => {
                    let key_exchange = SshKeyExchange {
                        cookie: pkt.cookie.to_vec(),
                        kex_algs: self.bytes_to_string_vec(pkt.kex_algs),
                        server_host_key_algs: self.bytes_to_string_vec(pkt.server_host_key_algs),
                        encryption_algs_client_to_server: self
                            .bytes_to_string_vec(pkt.encr_algs_client_to_server),
                        encryption_algs_server_to_client: self
                            .bytes_to_string_vec(pkt.encr_algs_server_to_client),
                        mac_algs_client_to_server: self
                            .bytes_to_string_vec(pkt.mac_algs_client_to_server),
                        mac_algs_server_to_client: self
                            .bytes_to_string_vec(pkt.mac_algs_server_to_client),
                        compression_algs_client_to_server: self
                            .bytes_to_string_vec(pkt.comp_algs_client_to_server),
                        compression_algs_server_to_client: self
                            .bytes_to_string_vec(pkt.comp_algs_server_to_client),
                        languages_client_to_server: self
                            .bytes_to_string_vec(pkt.langs_client_to_server),
                        languages_server_to_client: self
                            .bytes_to_string_vec(pkt.langs_server_to_client),
                        first_kex_packet_follows: pkt.first_kex_packet_follows,
                    };

                    self.key_exchange = Some(key_exchange);
                }
                e => log::debug!("Could not parse data as a SSH KeyExchange packet: {:?}", e),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
    }

    pub(crate) fn parse_dh_client_init(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => match pkt {
                SshPacket::DiffieHellmanInit(pkt) => {
                    let dh_init = SshDhInit { e: pkt.e.to_vec() };

                    self.client_dh_key_exchange = Some(dh_init);
                }
                e => log::debug!(
                    "Could not parse data as a SSH DiffieHellmanInit packet: {:?}",
                    e
                ),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
    }

    pub(crate) fn parse_dh_server_response(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => match pkt {
                SshPacket::DiffieHellmanReply(pkt) => {
                    let dh_response = SshDhResponse {
                        pubkey_and_certs: pkt.pubkey_and_cert.to_vec(),
                        f: pkt.f.to_vec(),
                        signature: pkt.signature.to_vec(),
                    };

                    self.server_dh_key_exchange = Some(dh_response);
                }
                e => log::debug!(
                    "Could not parse data as a SSH DiffieHellmanReply packet: {:?}",
                    e
                ),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
    }

    /// Parse a new keys packet. Return length of remaining data.
    pub(crate) fn parse_new_keys(&mut self, data: &[u8], dir: bool) -> usize {
        let mut remaining = 0;
        match ssh_parser::parse_ssh_packet(data) {
            Ok((rem, (pkt, _))) => match pkt {
                SshPacket::NewKeys => {
                    let new_keys = SshNewKeys;
                    remaining = rem.len();
                    if dir {
                        self.client_new_keys = Some(new_keys);
                    } else {
                        self.server_new_keys = Some(new_keys);
                    }
                }
                e => log::debug!("Could not parse data as a SSH NewKeys packet: {:?}", e),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
        remaining
    }

    pub(crate) fn process(&mut self, data: &[u8], dir: bool) -> ParseResult {
        let mut status = ParseResult::Continue(0);
        log::trace!("process ({} bytes)", data.len());

        let ssh_identifier = b"SSH-";
        if data
            .windows(ssh_identifier.len())
            .position(|window| window == ssh_identifier)
            .map(|p| &data[p..])
            .is_some()
        {
            self.parse_version_exchange(data, dir);
            status = ParseResult::Continue(0);
        } else {
            match ssh_parser::parse_ssh_packet(data) {
                Ok((_, (pkt, _))) => {
                    match pkt {
                        SshPacket::KeyExchange(_) => {
                            self.parse_key_exchange(data);
                            status = ParseResult::Continue(0);
                        }
                        SshPacket::DiffieHellmanInit(_) => {
                            self.parse_dh_client_init(data);
                            status = ParseResult::Continue(0);
                        }
                        SshPacket::DiffieHellmanReply(_) => {
                            self.parse_dh_server_response(data);
                            status = ParseResult::Continue(0);
                        }
                        SshPacket::NewKeys => {
                            let remaining = self.parse_new_keys(data, dir);

                            // finish parsing when client and server have both sent a NewKeys packet
                            if self.client_new_keys.is_some() && self.server_new_keys.is_some() {
                                if remaining > 0 && remaining < data.len() {
                                    self.last_body_offset = Some(data.len() - remaining - 1);
                                }
                                return ParseResult::HeadersDone(0);
                            }
                            status = ParseResult::Continue(0);
                        }
                        _ => (),
                    }
                }
                e => {
                    log::debug!("parse error: {:?}", e);
                    status = ParseResult::Skipped;
                }
            }
        }
        status
    }
}
