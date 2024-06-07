//! Quic Header parser
//! Custom Quic Parser with many design choices borrowed from
//! [Wireshark Quic Disector](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-quic.c)
//!
use crate::protocols::stream::quic::header::{QuicLongHeader, QuicShortHeader};
use crate::protocols::stream::quic::QuicPacket;
use crate::protocols::stream::{
    ConnParsable, ConnState, L4Pdu, ParseResult, ProbeResult, Session, SessionData,
};
use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct QuicParser {
    /// Maps session ID to Quic transaction
    sessions: HashMap<usize, QuicPacket>,
    /// Total sessions ever seen (Running session ID)
    cnt: usize,
}

impl ConnParsable for QuicParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.process(data)
        } else {
            log::warn!("Malformed packet on parse");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        if pdu.length() < 5 {
            return ProbeResult::Unsure;
        }

        let offset = pdu.offset();
        let length = pdu.length();

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            // Check if Fixed Bit is set
            if (data[0] & 0x40) == 0 {
                return ProbeResult::NotForUs;
            }

            if (data[0] & 0x80) != 0 {
                // Potential Long Header
                if data.len() < 6 {
                    return ProbeResult::Unsure;
                }

                // Check if version is known
                let version = ((data[1] as u32) << 24)
                    | ((data[2] as u32) << 16)
                    | ((data[3] as u32) << 8)
                    | (data[4] as u32);
                match QuicVersion::from_u32(version) {
                    QuicVersion::Unknown => ProbeResult::NotForUs,
                    _ => ProbeResult::Certain,
                }
            } else {
                ProbeResult::Unsure
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        self.sessions.remove(&session_id).map(|quic| Session {
            data: SessionData::Quic(Box::new(quic)),
            id: session_id,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain()
            .map(|(session_id, quic)| Session {
                data: SessionData::Quic(Box::new(quic)),
                id: session_id,
            })
            .collect()
    }

    fn session_match_state(&self) -> ConnState {
        ConnState::Parsing
    }
    fn session_nomatch_state(&self) -> ConnState {
        ConnState::Parsing
    }
}

/// Supported Quic Versions
#[derive(Debug, PartialEq, Eq, Hash)]
enum QuicVersion {
    ReservedNegotiation = 0x00000000,
    Rfc9000 = 0x00000001, // Quic V1
    Rfc9369 = 0x6b3343cf, // Quic V2
    Unknown,
}

impl QuicVersion {
    fn from_u32(version: u32) -> Self {
        match version {
            0x00000000 => QuicVersion::ReservedNegotiation,
            0x00000001 => QuicVersion::Rfc9000,
            0x6b3343cf => QuicVersion::Rfc9369,
            _ => QuicVersion::Unknown,
        }
    }
}

/// Errors Thrown by Quic Parser. These are handled by retina and used to skip packets.
#[derive(Debug)]
pub enum QuicError {
    FixedBitNotSet,
    PacketTooShort,
    UnknownVersion,
    ShortHeader,
}

impl QuicPacket {
    /// Processes the connection ID bytes array to a hex string
    pub fn vec_u8_to_hex_string(vec: &[u8]) -> String {
        vec.iter()
            .map(|&byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join("")
    }

    /// Parses Quic packet from bytes
    pub fn parse_from(data: &[u8]) -> Result<QuicPacket, QuicError> {
        if data.len() <= 2 {
            return Err(QuicError::PacketTooShort);
        }
        if (data[0] & 0x40) == 0 {
            return Err(QuicError::FixedBitNotSet);
        }
        if (data[0] & 0x80) != 0 {
            // Long Header
            if data.len() < 7 {
                return Err(QuicError::PacketTooShort);
            }
            let version = ((data[1] as u32) << 24)
                | ((data[2] as u32) << 16)
                | ((data[3] as u32) << 8)
                | (data[4] as u32);
            if QuicVersion::from_u32(version) == QuicVersion::Unknown {
                return Err(QuicError::UnknownVersion);
            }

            let packet_type = (data[0] & 0x30) >> 4;
            let type_specific = data[0] & 0x0F;

            let dcid_len = data[5];
            let dcid_start = 6;
            // There's a +2 in this size check because we need enough space to check the SCID length
            if data.len() < (dcid_start + dcid_len as usize + 2) {
                return Err(QuicError::PacketTooShort);
            }
            let dcid_bytes = &data[dcid_start..dcid_start + dcid_len as usize];
            let dcid = QuicPacket::vec_u8_to_hex_string(dcid_bytes);
            let scid_len = data[dcid_start + dcid_len as usize];
            let scid_start = dcid_start + dcid_len as usize + 1;
            if data.len() < (scid_start + scid_len as usize + 1) {
                return Err(QuicError::PacketTooShort);
            }
            let scid_bytes = &data[scid_start..scid_start + scid_len as usize];
            let scid = QuicPacket::vec_u8_to_hex_string(scid_bytes);

            // Counts all bytes remaining
            let payload_bytes_count = data.len() - scid_start - scid_len as usize;
            Ok(QuicPacket {
                payload_bytes_count: payload_bytes_count as u16,
                short_header: None,
                long_header: Some(QuicLongHeader {
                    packet_type,
                    type_specific,
                    version,
                    dcid_len,
                    dcid,
                    scid_len,
                    scid,
                }),
            })
        } else {
            // Short Header
            let mut max_dcid_len = 20;
            if data.len() < 1 + max_dcid_len {
                max_dcid_len = data.len() - 1;
            }
            let dcid_bytes = data[1..1 + max_dcid_len].to_vec();
            // Counts all bytes remaining
            let payload_bytes_count = data.len() - 1 - max_dcid_len;
            Ok(QuicPacket {
                short_header: Some(QuicShortHeader {
                    dcid: None,
                    dcid_bytes,
                }),
                long_header: None,
                payload_bytes_count: payload_bytes_count as u16,
            })
        }
    }
}

impl QuicParser {
    fn process(&mut self, data: &[u8]) -> ParseResult {
        if let Ok(quic) = QuicPacket::parse_from(data) {
            let session_id = self.cnt;
            self.sessions.insert(session_id, quic);
            self.cnt += 1;
            ParseResult::Done(session_id)
        } else {
            ParseResult::Skipped
        }
    }
}
