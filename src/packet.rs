use anyhow::{anyhow, Error, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Seek, Write};
use std::net::SocketAddr;
use tracing::{info, span, trace, warn, Level};

use crate::connection::{QuicConnection, QuicLevel};
use crate::crypto::{QuicCrypto, QUIC_TAG_LENGTH};
use crate::frame::QuicFrame;
use crate::tls::TLS_AES_128_GCM_SHA256;
use crate::utils::{
    decode_variable_length, encode_variable_length, encode_variable_length_force_two_bytes,
    write_cursor_bytes_with_pos,
};

pub(crate) const DEFAULT_INITIAL_PACKET_SIZE: u16 = 1200;
const DEFAULT_MTU: u16 = 1472; // 1500 - udp header 8 - ip header 20

const QUIC_PACKET_LENGTH_FIELD_SIZE: u16 = 2;

// Fixed Bit:
// The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
// Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded.
// A value of 1 for this bit allows QUIC to coexist with other protocols;
const FIXED_BIT: u8 = 0x40;
// Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet.
const QUIC_MAX_CONNECTION_ID_LENGTH: u8 = 20;
// Header Form:
// The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers.
const LONG_HEADER_FORM: u8 = 0x80;
const SHORT_HEADER_FORM: u8 = 0x00;
const KEY_PHASE: u8 = 0x04;

// Type-Specific Bits:
// The semantics of the lower four bits (those with a mask of 0x0f) of byte 0 are determined by the packet type.

// Version:
// The QUIC Version is a 32-bit field that follows the first byte.
// This field indicates the version of QUIC that is in use
// and determines how the rest of the protocol fields are interpreted
const QUIC_VERSION: u32 = 1;

// https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5
const QUIC_RETRY_INTEGRITY_TAG_SIZE: u16 = 16;

#[derive(Debug)]
struct QuicPacketNumber {
    truncated_pn: u32,
    packet_size: u8,
}

#[allow(dead_code)]
pub(crate) struct QuicLongHeaderPacket<'a> {
    packet_type: LongHeaderType,
    level: QuicLevel,
    from: SocketAddr,
    flag: u8,        // unprotected
    pn: Option<u64>, // unprotected
    dcid: Vec<u8>,
    scid: Vec<u8>,
    length: Option<u64>,
    raw_payload: &'a [u8], // encrypted
    payload: Vec<u8>,      // decrypted
}

#[allow(dead_code)]
pub(crate) struct QuicShortHeaderPacket<'a> {
    from: SocketAddr,
    flag: u8, // unprotected
    pn: u64,  // unprotected
    dcid: Vec<u8>,
    length: u64,
    raw_payload: &'a [u8], // encrypted
    payload: Vec<u8>,      // decrypted
}

// Long Packet Type:
// The next two bits (those with a mask of 0x30) of byte 0 contain a packet type.
// Type	Name	Section
// 0x00	Initial	Section 17.2.2
// 0x01	0-RTT	Section 17.2.3
// 0x02	Handshake	Section 17.2.4
// 0x03	Retry	Section 17.2.5
#[derive(Debug)]
pub(crate) enum LongHeaderType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl TryFrom<u8> for LongHeaderType {
    type Error = Error;

    fn try_from(flag: u8) -> Result<Self, Self::Error> {
        match (flag & 0x30) >> 4 {
            0x00 => Ok(LongHeaderType::Initial),
            0x01 => Ok(LongHeaderType::ZeroRtt),
            0x02 => Ok(LongHeaderType::Handshake),
            0x03 => Ok(LongHeaderType::Retry),
            _ => Err(anyhow!("Invalid value for LongHeaderType")),
        }
    }
}

impl From<LongHeaderType> for u8 {
    fn from(val: LongHeaderType) -> Self {
        match val {
            LongHeaderType::Initial => 0x00,
            LongHeaderType::ZeroRtt => 0x01,
            LongHeaderType::Handshake => 0x02,
            LongHeaderType::Retry => 0x03,
        }
    }
}

pub(crate) enum QuicPacket<'a> {
    LongHeader(QuicLongHeaderPacket<'a>),
    ShortHeader(QuicShortHeaderPacket<'a>),
}

impl QuicPacket<'_> {
    pub(crate) fn start_tls_handshake(qconn: &mut QuicConnection, is_retry: bool) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9001#section-5.2-9
        let secret = if !is_retry {
            &qconn.org_dcid
        } else {
            qconn
                .dcid
                .as_ref()
                .ok_or_else(|| anyhow!("Must have dcid here"))?
        };

        qconn.crypto.create_initial_secrets(secret)?;

        qconn.tls.start_tls_handshake()?;

        qconn.consume_tls_send_queue()?;

        Self::update_quic_send_queue(qconn, qconn.quic_config.first_initial_packet_size)?;

        Ok(())
    }

    fn update_quic_send_queue_helper(
        qconn: &mut QuicConnection,
        level: QuicLevel,
        remain: u16,
        bufs: &mut Vec<Vec<u8>>,
    ) -> Result<u16> {
        // TODO: Check if need to generate the Ack frame

        let send_ctx = match level {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        // Check if need to create packet
        if send_ctx.is_send_queue_empty() {
            return Ok(remain);
        }

        let pkt_buf = match level {
            QuicLevel::Initial => Self::create_initial_packet(qconn, remain)?,
            QuicLevel::Handshake => Self::create_handshake_packet(qconn, remain)?,
            QuicLevel::Application => Self::create_application_packet(qconn, remain)?,
        };

        let consumed_size = if let Some(pkt_buf) = pkt_buf {
            let len = pkt_buf.len();
            bufs.push(pkt_buf);
            len
        } else {
            0
        };

        let new_remain = remain.checked_sub(consumed_size as u16).ok_or_else(|| {
            anyhow!(
                "Construct QUIC packet, remain {}, consumed {}",
                remain,
                consumed_size
            )
        })?;

        trace!(
            "Construct the {:?} packet, remain {}, consumed_size {}",
            level,
            remain,
            consumed_size
        );

        Ok(new_remain)
    }

    fn update_quic_send_queue(qconn: &mut QuicConnection, mtu: u16) -> Result<()> {
        loop {
            // TODO, MTU discovery
            let udp_datagram_size = mtu;

            let mut datagram_bufs = vec![];
            let remain = Self::update_quic_send_queue_helper(
                qconn,
                QuicLevel::Initial,
                udp_datagram_size,
                &mut datagram_bufs,
            )?;
            let remain = Self::update_quic_send_queue_helper(
                qconn,
                QuicLevel::Handshake,
                remain,
                &mut datagram_bufs,
            )?;
            Self::update_quic_send_queue_helper(
                qconn,
                QuicLevel::Application,
                remain,
                &mut datagram_bufs,
            )?;

            if !datagram_bufs.is_empty() {
                qconn.update_packet_send_queue(datagram_bufs);
            }

            if qconn.is_all_send_queue_empty() {
                break;
            }
        }
        Ok(())
    }

    fn create_initial_packet(
        qconn: &mut QuicConnection,
        udp_datagram_remaining: u16,
    ) -> Result<Option<Vec<u8>>> {
        let span = span!(Level::TRACE, "create_initial_packet");
        let _enter = span.enter();

        let mut sndbuf = vec![];
        let mut cursor = Cursor::new(&mut sndbuf);

        // https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
        // An Initial packet uses long headers with a type value of 0x00.
        // It carries the first CRYPTO frames sent by the client and server
        // to perform key exchange, and it carries ACK frames in either direction.
        // Initial Packet {
        //   Header Form (1) = 1,
        //   Fixed Bit (1) = 1,
        //   Long Packet Type (2) = 0,
        //   Reserved Bits (2),                # Protected
        //   Packet Number Length (2),         # Protected
        //   Version (32),
        //   Destination Connection ID Length (8),
        //   Destination Connection ID (0..160),
        //   Source Connection ID Length (8),
        //   Source Connection ID (0..160),
        //   Token Length (i),
        //   Token (..),
        //   Length (i),
        //   Packet Number (8..32),            # Protected
        //   Packet Payload (8..),
        // }
        let mut flag = LONG_HEADER_FORM
            | FIXED_BIT
            | (<LongHeaderType as Into<u8>>::into(LongHeaderType::Initial) << 4);

        // In the initial packet, what's the Type-Specific Bits is on the below:
        //
        // Reserved Bits:  Two bits (those with a mask of 0x0c) of byte 0 are
        //   reserved across multiple packet types.  These bits are protected
        //   using header protection; see Section 5.4 of [QUIC-TLS].  The value
        //   included prior to protection MUST be set to 0.  An endpoint MUST
        //   treat receipt of a packet that has a non-zero value for these bits
        //   after removing both packet and header protection as a connection
        //   error of type PROTOCOL_VIOLATION.  Discarding such a packet after
        //   only removing header protection can expose the endpoint to
        //   attacks; see Section 9.5 of [QUIC-TLS].
        //
        // Packet Number Length:  In packet types that contain a Packet Number
        //   field, the least significant two bits (those with a mask of 0x03)
        //   of byte 0 contain the length of the Packet Number field, encoded
        //   as an unsigned two-bit integer that is one less than the length of
        //   the Packet Number field in bytes.  That is, the length of the
        //   Packet Number field is the value of this field plus one.  These
        //   bits are protected using header protection; see Section 5.4 of
        //   [QUIC-TLS].
        let flag_pos = cursor.position();

        /* now we have prepared our first byte */
        cursor.write_u8(flag)?;

        /* only support version 1 */
        cursor.write_u32::<BigEndian>(QUIC_VERSION)?;

        /* prepare dcid and scid */
        let dcid = if qconn.dcid.is_none() {
            &qconn.org_dcid
        } else {
            qconn.dcid.as_ref().unwrap()
        };
        let dcid_len = dcid.len();
        cursor.write_u8(dcid_len as u8)?;
        cursor.write_all(dcid)?;

        let scid_len = qconn.scid.len();
        cursor.write_u8(scid_len as u8)?;
        cursor.write_all(&qconn.scid)?;

        info!(
            "Now we have dcid {:x?} and scid {:x?} in initial packet",
            &qconn.org_dcid, &qconn.scid
        );

        // Token Length:
        // A variable-length integer specifying the length of the Token field, in bytes.
        // This value is 0 if no token is present. Initial packets sent by the server MUST set the Token Length field to 0;
        // clients that receive an Initial packet with a non-zero Token Length field MUST either discard the packet
        // or generate a connection error of type PROTOCOL_VIOLATION.
        let token_size = if let Some(token) = qconn.retry_token.as_ref() {
            let token_length_size = encode_variable_length(&mut cursor, token.len() as u64)?;
            cursor.write_all(token)?;
            token.len() + token_length_size as usize
        } else {
            let initial_token_len = 0;
            encode_variable_length(&mut cursor, initial_token_len)?;
            1
        };

        // Calculate QUIC packet length
        // QUIC packet length = packet_number_field_size + encrypted data size + AEAD tag size (16bytes)
        // So we need to figure out what's the Packet Number, since it's truncated in QUIC packet
        let pn = encode_packet_number_field_size(
            qconn.init_send.next_pn,
            *qconn.init_send.largest_acked.as_ref().unwrap_or(&0),
        )?;

        flag |= (pn
            .packet_size
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Bad packet field size {}", pn.packet_size))?)
            as u8;
        trace!(
            "Now we have our new flag {:x} old flag {:x}, and pn {:?}",
            flag,
            cursor.get_ref()[flag_pos as usize],
            pn
        );
        write_cursor_bytes_with_pos(&mut cursor, flag_pos, &[flag])?;
        trace!(
            "Now we have our new flag {:x}, and pos {:?}",
            cursor.get_ref()[flag_pos as usize],
            cursor.position()
        );

        let udp_datagram_size = udp_datagram_remaining;
        // FLAG_SIZE + QUIC_VERSION_SIZE + DCID_LEN_FIELD_SIZE + DCID_SIZE + DCID_LEN_FIELD_SIZE + SCID_SIZE + TOKEN_SIZE
        let quic_packet_header_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_size;
        if udp_datagram_size < quic_packet_header_len as u16 {
            return Ok(None);
        }

        // Write initial packet size
        let initial_packet_len = udp_datagram_size - quic_packet_header_len as u16;
        // remain_len == packet number field + plain_text_data size + tag size
        let remain_len = initial_packet_len - QUIC_PACKET_LENGTH_FIELD_SIZE;
        let length_pos = cursor.position();
        cursor.seek_relative(QUIC_PACKET_LENGTH_FIELD_SIZE as i64)?;
        trace!(
            "Now our initial QUIC packet header size is {}, and possible packet length is {}",
            quic_packet_header_len,
            initial_packet_len
        );
        trace!(
            "Now our initial QUIC packet length field size is 2, remain_len is {}, pos {}, within UDP datagram size {}",
            remain_len, cursor.position(),
            udp_datagram_size
        );

        // Write packet number
        let packet_number_start = cursor.position();
        match pn.packet_size {
            1 => cursor.write_u8(pn.truncated_pn as u8)?,
            2 => cursor.write_u16::<BigEndian>(pn.truncated_pn as u16)?,
            3 => cursor.write_u24::<BigEndian>(pn.truncated_pn as u32)?,
            4 => cursor.write_u32::<BigEndian>(pn.truncated_pn as u32)?,
            _ => return Err(anyhow!("Bad packet field size {}", pn.packet_size)),
        }

        let encrypted_start_pos = cursor.position();
        trace!("Prepare initial payload at pos {}", encrypted_start_pos);

        let mut payload: Vec<u8> = vec![];
        let mut payload_cursor = Cursor::new(&mut payload);
        let mut need_padding = false;
        while let Some(frame) = qconn.init_send.consume_send_queue() {
            let payload_len = payload_cursor.position();
            let res = frame.serialize(&mut payload_cursor, remain_len - payload_len as u16)?;
            if res {
                if frame.is_crypto_frame() {
                    need_padding = true;
                }
            } else {
                // Restore the send queue, if QUIC payload size is not enough
                qconn.init_send.insert_send_queue_front(frame);
                break;
            }
        }

        let payload_len = payload_cursor.position();
        if payload_len == 0 {
            return Ok(None);
        }

        if need_padding {
            let padding_frame_size = remain_len
                .checked_sub(pn.packet_size as u16)
                .ok_or_else(|| {
                    anyhow!(
                        "Bad packet number size {}, initial_packet_len {}",
                        pn.packet_size,
                        initial_packet_len
                    )
                })?
                .checked_sub(payload_len as u16)
                .ok_or_else(|| {
                    anyhow!(
                        "Bad crypto frame size {}, initial_packet_len {}",
                        payload_len,
                        initial_packet_len
                    )
                })?
                .checked_sub(QUIC_TAG_LENGTH as u16)
                .ok_or_else(|| {
                    anyhow!(
                        "Bad QUIC tag length {}, initial_packet_len {}",
                        QUIC_TAG_LENGTH,
                        initial_packet_len
                    )
                })?;
            QuicFrame::create_padding_frame(&mut payload_cursor, padding_frame_size)?;
            trace!("Added padding frame at pos {}", payload_cursor.position());
        }

        // Update the packet length
        let end_pos = cursor.position();
        let packet_length =
            end_pos - packet_number_start + payload.len() as u64 + QUIC_TAG_LENGTH as u64;
        cursor.set_position(length_pos);
        encode_variable_length_force_two_bytes(&mut cursor, packet_length)?;
        cursor.set_position(end_pos);
        trace!("Finish initial packet with length {}", packet_length);

        // Encrypt
        // the AEAD function is applied prior to applying header protection
        let encrypted_data = qconn.crypto.encrypt_packet(
            QuicLevel::Initial,
            TLS_AES_128_GCM_SHA256,
            &payload,
            // The associated data, A, for the AEAD is the contents of the QUIC header,
            // starting from the first byte of either the short or long header, up to and including the unprotected packet number.
            &cursor.get_ref()[..encrypted_start_pos as usize],
            qconn.init_send.next_pn,
        )?;
        qconn.init_send.next_pn += 1;
        cursor.set_position(encrypted_start_pos);
        cursor.write_all(&encrypted_data)?;

        // Header Protection
        // Example: https://www.rfc-editor.org/rfc/rfc9001.html#section-a.2
        qconn.crypto.add_header_protection(
            QuicLevel::Initial,
            cursor.get_mut(),
            packet_number_start,
            pn.packet_size,
        )?;

        trace!("Initial packet size {}", cursor.position());

        Ok(Some(sndbuf))
    }

    pub fn create_application_packet(
        qconn: &mut QuicConnection,
        udp_datagram_remaining: u16,
    ) -> Result<Option<Vec<u8>>> {
        let span = span!(Level::TRACE, "create_application_packet");
        let _enter = span.enter();

        // https://www.rfc-editor.org/rfc/rfc9000.html#name-1-rtt-packet
        // 1-RTT Packet {
        //   Header Form (1) = 0,
        //   Fixed Bit (1) = 1,
        //   Spin Bit (1),
        //   Reserved Bits (2),         # Protected
        //   Key Phase (1),             # Protected
        //   Packet Number Length (2),  # Protected
        //   Destination Connection ID (0..160),
        //   Packet Number (8..32),     # Protected
        //   Protected Payload (0..24), # Skipped Part
        //   Protected Payload (128),   # Sampled Part
        //   Protected Payload (..),    # Remainder
        // }

        let mut sndbuf = vec![];
        let mut cursor = Cursor::new(&mut sndbuf);

        let flag_pos = cursor.position();
        let mut flag = SHORT_HEADER_FORM | FIXED_BIT;
        /* now we have prepared our first byte */
        cursor.write_u8(flag)?;

        /* prepare dcid and scid */
        let dcid = qconn
            .dcid
            .as_ref()
            .ok_or_else(|| anyhow!("Should have dcid here, when creating handshake packet"))?;
        cursor.write_all(dcid)?;

        let pn = encode_packet_number_field_size(
            qconn.app_send.next_pn,
            *qconn.app_send.largest_acked.as_ref().unwrap_or(&0),
        )?;

        // Write packet number
        let packet_number_start = cursor.position();
        match pn.packet_size {
            1 => cursor.write_u8(pn.truncated_pn as u8)?,
            2 => cursor.write_u16::<BigEndian>(pn.truncated_pn as u16)?,
            3 => cursor.write_u24::<BigEndian>(pn.truncated_pn as u32)?,
            4 => cursor.write_u32::<BigEndian>(pn.truncated_pn as u32)?,
            _ => return Err(anyhow!("Bad packet field size {}", pn.packet_size)),
        }

        let quic_header_size = cursor.position() as u16;
        if udp_datagram_remaining < quic_header_size {
            return Ok(None);
        }
        let max_payload_size = udp_datagram_remaining - quic_header_size - QUIC_TAG_LENGTH as u16;

        // Construct payload
        let mut payload: Vec<u8> = vec![];
        let mut payload_cursor = Cursor::new(&mut payload);

        while let Some(frame) = qconn.app_send.consume_send_queue() {
            let payload_len = payload_cursor.position();
            let res =
                frame.serialize(&mut payload_cursor, max_payload_size - payload_len as u16)?;
            if !res {
                qconn.app_send.insert_send_queue_front(frame);
                break;
            }
        }

        if payload.is_empty() {
            return Ok(None);
        }

        flag |= (pn
            .packet_size
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Bad packet field size {}", pn.packet_size))?)
            as u8;
        trace!(
            "Now we have our new flag {:x}, real pn {} and pn {:?} in application packet",
            flag,
            qconn.app_send.next_pn,
            pn
        );
        write_cursor_bytes_with_pos(&mut cursor, flag_pos, &[flag])?;

        // Encrypt
        // the AEAD function is applied prior to applying header protection
        let encrypted_data = qconn.crypto.encrypt_packet(
            QuicLevel::Application,
            qconn.tls.get_selected_cipher_suite()?,
            &payload,
            // The associated data, A, for the AEAD is the contents of the QUIC header,
            // starting from the first byte of either the short or long header, up to and including the unprotected packet number.
            &cursor.get_ref()[..cursor.position() as usize],
            qconn.app_send.next_pn,
        )?;
        qconn.app_send.next_pn += 1;

        cursor.write_all(&encrypted_data)?;

        // Header Protection
        // Example: https://www.rfc-editor.org/rfc/rfc9001.html#section-a.2
        qconn.crypto.add_header_protection(
            QuicLevel::Application,
            cursor.get_mut(),
            packet_number_start,
            pn.packet_size,
        )?;

        trace!("Application packet size {}", cursor.position());

        Ok(Some(sndbuf))
    }

    fn create_handshake_packet(
        qconn: &mut QuicConnection,
        udp_datagram_remaining: u16,
    ) -> Result<Option<Vec<u8>>> {
        let span = span!(Level::TRACE, "create_handshake_packet");
        let _enter = span.enter();

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.4
        // Handshake Packet {
        //   Header Form (1) = 1,
        //   Fixed Bit (1) = 1,
        //   Long Packet Type (2) = 2,
        //   Reserved Bits (2),                # Protected
        //   Packet Number Length (2),         # Protected
        //   Version (32),
        //   Destination Connection ID Length (8),
        //   Destination Connection ID (0..160),
        //   Source Connection ID Length (8),
        //   Source Connection ID (0..160),
        //   Length (i),
        //   Packet Number (8..32),            # Protected
        //   Packet Payload (8..),             # Encrypted
        // }

        let mut sndbuf = vec![];
        let mut cursor = Cursor::new(&mut sndbuf);

        let flag_pos = cursor.position();
        let mut flag = LONG_HEADER_FORM
            | FIXED_BIT
            | (<LongHeaderType as Into<u8>>::into(LongHeaderType::Handshake) << 4);

        /* now we have prepared our first byte */
        cursor.write_u8(flag)?;

        /* only support version 1 */
        cursor.write_u32::<BigEndian>(QUIC_VERSION)?;

        /* prepare dcid and scid */
        let dcid = qconn
            .dcid
            .as_ref()
            .ok_or_else(|| anyhow!("Should have dcid here, when creating handshake packet"))?;
        let dcid_len = dcid.len();
        cursor.write_u8(dcid_len as u8)?;
        cursor.write_all(dcid)?;

        let scid_len = qconn.scid.len();
        cursor.write_u8(scid_len as u8)?;
        cursor.write_all(&qconn.scid)?;

        info!(
            "Now we have dcid {:x?} and scid {:x?} in handshake packet",
            dcid, &qconn.scid
        );

        let pn = encode_packet_number_field_size(
            qconn.hs_send.next_pn,
            *qconn.hs_send.largest_acked.as_ref().unwrap_or(&0),
        )?;
        flag |= (pn
            .packet_size
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Bad packet field size {}", pn.packet_size))?)
            as u8;
        trace!(
            "Now we have our new flag {:x}, and pn {:?} in handshake packet",
            flag,
            pn
        );
        write_cursor_bytes_with_pos(&mut cursor, flag_pos, &[flag])?;

        // Prepare packet length
        let packet_length_pos_start = cursor.position();
        cursor.seek_relative(QUIC_PACKET_LENGTH_FIELD_SIZE as i64)?;

        // Write packet number
        let packet_number_start = cursor.position();
        match pn.packet_size {
            1 => cursor.write_u8(pn.truncated_pn as u8)?,
            2 => cursor.write_u16::<BigEndian>(pn.truncated_pn as u16)?,
            3 => cursor.write_u24::<BigEndian>(pn.truncated_pn as u32)?,
            4 => cursor.write_u32::<BigEndian>(pn.truncated_pn as u32)?,
            _ => return Err(anyhow!("Bad packet field size {}", pn.packet_size)),
        }

        // TODO: MTU Discovery
        let quic_header_size = cursor.position() as u16;
        if udp_datagram_remaining < quic_header_size {
            return Ok(None);
        }
        let max_payload_size = udp_datagram_remaining - quic_header_size - QUIC_TAG_LENGTH as u16;
        trace!(
            "We are preparing QUIC handshake packet, UDP datagram remaining {}, QUIC header size {}, \
            max_payload_size {}, aead tag length {}",
            udp_datagram_remaining,
            quic_header_size,
            max_payload_size,
            QUIC_TAG_LENGTH,
        );

        // Construct payload
        let mut payload: Vec<u8> = vec![];
        let mut payload_cursor = Cursor::new(&mut payload);

        while let Some(frame) = qconn.hs_send.consume_send_queue() {
            let payload_len = payload_cursor.position();
            let res =
                frame.serialize(&mut payload_cursor, max_payload_size - payload_len as u16)?;
            if !res {
                qconn.hs_send.insert_send_queue_front(frame);
                break;
            }
        }

        if payload.is_empty() {
            return Ok(None);
        }

        // Check and fill packet length
        let packet_length = payload.len() as u64 + pn.packet_size as u64 + QUIC_TAG_LENGTH as u64;
        trace!(
            "Creating handshake packet, packet length {}, packet_length_pos_start {}",
            packet_length,
            packet_length_pos_start
        );
        let org_pos = cursor.position();
        cursor.set_position(packet_length_pos_start);
        encode_variable_length_force_two_bytes(&mut cursor, packet_length)?;
        cursor.set_position(org_pos);

        // Encrypt
        // the AEAD function is applied prior to applying header protection
        let encrypted_data = qconn.crypto.encrypt_packet(
            QuicLevel::Handshake,
            qconn.tls.get_selected_cipher_suite()?,
            &payload,
            // The associated data, A, for the AEAD is the contents of the QUIC header,
            // starting from the first byte of either the short or long header, up to and including the unprotected packet number.
            &cursor.get_ref()[..cursor.position() as usize],
            qconn.hs_send.next_pn,
        )?;
        qconn.hs_send.next_pn += 1;

        cursor.write_all(&encrypted_data)?;

        // Header Protection
        // Example: https://www.rfc-editor.org/rfc/rfc9001.html#section-a.2
        qconn.crypto.add_header_protection(
            QuicLevel::Handshake,
            cursor.get_mut(),
            packet_number_start,
            pn.packet_size,
        )?;

        trace!("Handshake packet size {}", cursor.position());

        Ok(Some(sndbuf))
    }

    pub(crate) fn handle_quic_packet(
        rcvbuf: &[u8],
        qconn: &mut QuicConnection,
        source_addr: &SocketAddr,
    ) -> Result<()> {
        // We could have multiple QUIC packet in only one UDP datagram
        let mut offset = 0;
        while offset < rcvbuf.len() {
            let flag = rcvbuf[offset];
            trace!(
                "Start to process QUIC packet, offset {}, flag {:x}",
                offset,
                flag
            );
            let packet_size = if is_long_header(flag) {
                Self::handle_long_header_packet(&rcvbuf[offset..], qconn, source_addr)?
            } else {
                Self::handle_short_header_packet(&rcvbuf[offset..], qconn, source_addr)?
            };
            trace!(
                "Handle the last QUIC packet with size {packet_size}, offset {offset}, udp datagram size {}",
                rcvbuf.len()
            );
            offset += packet_size as usize;
        }

        if offset != rcvbuf.len() {
            return Err(anyhow!(
                "Now we got invalid QUIC packet, offset {}, udp datagram len {}",
                offset,
                rcvbuf.len()
            ));
        }

        Self::update_quic_send_queue(qconn, DEFAULT_MTU)?;

        Ok(())
    }

    fn handle_long_header_packet(
        rcvbuf: &[u8],
        qconn: &mut QuicConnection,
        source_addr: &SocketAddr,
    ) -> Result<u16> {
        let span = span!(
            Level::TRACE,
            "handle_long_header_packet",
            scid = ?qconn.scid.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(""),
            source = ?source_addr
        );
        let _enter = span.enter();

        let (pkt, consumed_size) =
            Self::handle_long_header_packet_helper(rcvbuf, qconn, source_addr)?;

        let pkt = QuicPacket::LongHeader(pkt);

        Self::update_packet_space(qconn, &pkt)?;
        QuicFrame::handle_quic_frame(qconn, &pkt)?;

        Ok(consumed_size)
    }

    pub(crate) fn get_packet_number(&self) -> Option<u64> {
        match self {
            Self::LongHeader(lpkt) => lpkt.pn,
            Self::ShortHeader(spkt) => Some(spkt.pn),
        }
    }

    pub(crate) fn get_packet_level(&self) -> QuicLevel {
        match self {
            Self::LongHeader(lpkt) => lpkt.level,
            Self::ShortHeader(_) => QuicLevel::Application,
        }
    }

    pub(crate) fn get_payload(&self) -> &[u8] {
        match self {
            Self::LongHeader(lpkt) => &lpkt.payload,
            Self::ShortHeader(spkt) => &spkt.payload,
        }
    }

    fn update_packet_space(qconn: &mut QuicConnection, pkt: &QuicPacket) -> Result<()> {
        let send_ctx = match pkt.get_packet_level() {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        // TODO: handle the packet reorder or packet loss scenario
        if let Some(pn) = pkt.get_packet_number() {
            send_ctx.largest_pn = send_ctx
                .largest_pn
                .map_or(Some(pn), |lpn| Some(pn.max(lpn)));

            trace!(
                "Update {:?} packet space, largest_pn {:?}",
                pkt.get_packet_level(),
                send_ctx.largest_pn
            );
        }

        Ok(())
    }

    fn handle_short_header_packet(
        rcvbuf: &[u8],
        qconn: &mut QuicConnection,

        source_addr: &SocketAddr,
    ) -> Result<u16> {
        let span = span!(
            Level::TRACE,
            "handle_short_header_packet",
            packet_len = ?rcvbuf.len(),
            scid = ?qconn.scid.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(""),
        );
        let _enter = span.enter();

        //  https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3
        //  1-RTT Packet {
        //   Header Form (1) = 0,
        //   Fixed Bit (1) = 1,
        //   Spin Bit (1),
        //   Reserved Bits (2),                   # Protected
        //   Key Phase (1),                       # Protected
        //   Packet Number Length (2),            # Protected
        //   Destination Connection ID (0..160),
        //   Packet Number (8..32),               # Protected
        //   Packet Payload (8..),
        // }

        let mut cursor = Cursor::new(rcvbuf);
        let flag = cursor.read_u8()?;

        // TODO: Check dcid
        let dcid_len = qconn.scid.len();
        let mut dcid = vec![0u8; dcid_len];
        cursor.read_exact(&mut dcid)?;

        trace!(
            "Processing the short QUIC packet, protected flag 0x{:x}, dcid {:x?}",
            flag,
            dcid
        );

        // Remove header protection and get packet number
        // Pn_offset is the start of the Packet Number field
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2
        let pn_offset = 1 + dcid_len;
        let (unprotected_flag, truncated_pn, pn_length) = qconn.crypto.remove_header_protection(
            QuicLevel::Application,
            &cursor,
            pn_offset as u64,
        )?;
        let real_pn = decode_packet_number_field_size(
            qconn.app_send.largest_pn.as_ref(),
            truncated_pn,
            pn_length << 3,
        )?;

        // TODO: key update
        let key_phase = unprotected_flag & KEY_PHASE;
        trace!(
            "Here we finally got real flag 0x{:x} and packet number {}, \
            largest_pn {:?}, key phase {}, in Application space",
            unprotected_flag,
            real_pn,
            qconn.app_send.largest_pn,
            key_phase
        );
        cursor.seek_relative(pn_length as i64)?;
        let length = rcvbuf.len() as u64 - cursor.position();

        // Decrypt payload
        let decrypted_start_pos = cursor.position();
        let decrypted_end_pos = cursor.get_ref().len();

        // Contruct aad from header protection
        let mut aad = vec![0u8; decrypted_start_pos as usize];
        aad.copy_from_slice(&cursor.get_ref()[..decrypted_start_pos as usize]);
        aad[0] = unprotected_flag;
        let pn_bytes = u32::to_be_bytes(truncated_pn);
        aad[pn_offset..pn_offset + pn_length as usize]
            .copy_from_slice(&pn_bytes[4 - pn_length as usize..]);

        let decrypted_data = qconn.crypto.decrypt_packet(
            QuicLevel::Application,
            qconn.tls.get_selected_cipher_suite()?,
            &cursor.get_ref()[decrypted_start_pos as usize..decrypted_end_pos],
            // The associated data, A, for the AEAD is the contents of the QUIC header,
            // starting from the first byte of either the short or long header,
            // up to and including the unprotected packet number.
            &aad,
            real_pn,
        )?;

        cursor.seek_relative((decrypted_data.len() + QUIC_TAG_LENGTH) as i64)?;

        let spkt = QuicShortHeaderPacket {
            from: *source_addr,
            flag: unprotected_flag,
            pn: real_pn,
            dcid,
            length,
            raw_payload: rcvbuf,
            payload: decrypted_data,
        };

        let pkt = QuicPacket::ShortHeader(spkt);
        Self::update_packet_space(qconn, &pkt)?;

        // Handle short header packet's payload
        QuicFrame::handle_quic_frame(qconn, &pkt)?;

        Ok(cursor.position() as u16)
    }

    pub fn handle_long_header_packet_helper<'b>(
        rcvbuf: &'b [u8],
        qconn: &mut QuicConnection,
        source_addr: &SocketAddr,
    ) -> Result<(QuicLongHeaderPacket<'b>, u16)> {
        // https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
        // An Initial packet uses long headers with a type value of 0x00.
        // It carries the first CRYPTO frames sent by the client and server
        // to perform key exchange, and it carries ACK frames in either direction.
        // Initial Packet {
        //   Header Form (1) = 1,
        //   Fixed Bit (1) = 1,
        //   Long Packet Type (2) = 0,
        //   Reserved Bits (2),                # Protected
        //   Packet Number Length (2),         # Protected
        //   Version (32),
        //   Destination Connection ID Length (8),
        //   Destination Connection ID (0..160),
        //   Source Connection ID Length (8),
        //   Source Connection ID (0..160),
        //   Token Length (i),
        //   Token (..),
        //   Length (i),
        //   Packet Number (8..32),            # Protected
        //   Packet Payload (8..),             # Encrypted
        // }
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.4
        // Handshake Packet {
        //   Header Form (1) = 1,
        //   Fixed Bit (1) = 1,
        //   Long Packet Type (2) = 2,
        //   Reserved Bits (2),                # Protected
        //   Packet Number Length (2),         # Protected
        //   Version (32),
        //   Destination Connection ID Length (8),
        //   Destination Connection ID (0..160),
        //   Source Connection ID Length (8),
        //   Source Connection ID (0..160),
        //   Length (i),
        //   Packet Number (8..32),            # Protected
        //   Packet Payload (8..),             # Encrypted
        // }
        let rcvbuf_len = rcvbuf.len();
        let mut cursor = Cursor::new(rcvbuf);
        let flag = cursor.read_u8()?;
        let header_type = LongHeaderType::try_from(flag)?;
        let (level, send_ctx) = match header_type {
            LongHeaderType::Initial => (QuicLevel::Initial, &qconn.init_send),
            LongHeaderType::Retry => (QuicLevel::Initial, &qconn.init_send),
            LongHeaderType::Handshake => (QuicLevel::Handshake, &qconn.hs_send),
            _ => unimplemented!(),
        };

        let version = cursor.read_u32::<BigEndian>()?;
        let dcid_len = cursor.read_u8()?;
        if dcid_len > QUIC_MAX_CONNECTION_ID_LENGTH {
            return Err(anyhow!(
                "Invalid QUIC connection id in {:?}, bad dcid length {}",
                level,
                dcid_len
            ));
        }
        let mut dcid = vec![0u8; dcid_len as usize];
        cursor.read_exact(&mut dcid)?;

        let scid_len = cursor.read_u8()?;
        if scid_len > QUIC_MAX_CONNECTION_ID_LENGTH {
            return Err(anyhow!(
                "Invalid QUIC connection id in {:?}, bad scid length {}",
                level,
                scid_len
            ));
        }
        let mut scid = vec![0u8; scid_len as usize];
        cursor.read_exact(&mut scid)?;

        // TODO: should verify dcid, scid, version and other staff
        if qconn.dcid.is_none() {
            trace!("Got first dcid {:x?} on our side", &scid);
            qconn.dcid = Some(scid.clone());
        }

        if matches!(header_type, LongHeaderType::Retry) {
            let tmp_pkt = QuicLongHeaderPacket {
                packet_type: header_type,
                level,
                from: *source_addr,
                flag,
                pn: None,
                dcid: dcid.clone(),
                scid: scid.clone(),
                length: None,
                raw_payload: rcvbuf,
                payload: vec![],
            };
            // After the client has received and processed an Initial or Retry packet from the server,
            // it MUST discard any subsequent Retry packets that it receives.
            if qconn.retry_token.is_some() {
                info!(
                    "Received multiple retry packet with size {}, discarding this packet",
                    rcvbuf_len
                );
                return Ok((tmp_pkt, rcvbuf_len as u16));
            }

            let remain_len = rcvbuf_len as u64 - cursor.position();
            trace!(
                "Now start to handle retry packet with size {}, remain_len {}",
                rcvbuf_len,
                remain_len
            );
            if (remain_len as u16) < QUIC_RETRY_INTEGRITY_TAG_SIZE + 1 {
                return Err(anyhow!(
                    "Received retry packet must have a token, lack of remain_len {}",
                    remain_len
                ));
            }

            let tag =
                &cursor.get_ref()[rcvbuf_len - QUIC_RETRY_INTEGRITY_TAG_SIZE as usize..rcvbuf_len];
            let retry_token = &cursor.get_ref()
                [cursor.position() as usize..rcvbuf_len - QUIC_RETRY_INTEGRITY_TAG_SIZE as usize];
            trace!(
                "Received retry packet, retry_token size {} {:x?}, tag {:x?}",
                retry_token.len(),
                retry_token,
                tag,
            );

            // https://www.rfc-editor.org/rfc/rfc9001#retry-pseudo
            // Construct retry pseudo-packet for tag validation
            let mut add = vec![];
            let mut add_cursor = Cursor::new(&mut add);
            add_cursor.write_u8(qconn.org_dcid.len() as u8)?;
            add_cursor.write_all(&qconn.org_dcid)?;
            add_cursor.write_u8(flag)?;
            add_cursor.write_u32::<BigEndian>(QUIC_VERSION)?;
            add_cursor.write_u8(dcid.len() as u8)?;
            add_cursor.write_all(&dcid)?;
            add_cursor.write_u8(scid.len() as u8)?;
            add_cursor.write_all(&scid)?;
            add_cursor.write_all(retry_token)?;

            if !QuicCrypto::validate_retry_packet_tag(&add, tag)? {
                warn!(
                    "Retry packet tag is invalid, discarding this packet, add size {} {:x?}",
                    add.len(),
                    add,
                );
                return Ok((tmp_pkt, rcvbuf_len as u16));
            }

            // A Retry packet does not include a packet number and cannot be explicitly acknowledged by a client.
            qconn.retry_token = Some(retry_token.to_vec());
            trace!("Got correct retry token, will send initial packet again");

            Self::start_tls_handshake(qconn, true)?;

            return Ok((tmp_pkt, rcvbuf_len as u16));
        }

        if level == QuicLevel::Initial {
            let token_len = decode_variable_length(&mut cursor)?;
            let mut token = vec![0u8; token_len as usize];
            cursor.read_exact(&mut token)?;
        }
        let length = decode_variable_length(&mut cursor)?;
        let packet_header_size = cursor.position();
        let consumed_size = length as u16 + packet_header_size as u16;

        trace!(
            "Now we have new {:?} QUIC packet header_size {}, \
            consumed_size {}, length {}, protected flag {:x}, \
            dcid {:x?}, scid {:x?}, version {}",
            header_type,
            packet_header_size,
            consumed_size,
            length,
            flag,
            &dcid,
            &scid,
            version
        );

        let (unprotected_flag, truncated_pn, pn_length) =
            qconn
                .crypto
                .remove_header_protection(level, &cursor, packet_header_size)?;

        let real_pn = decode_packet_number_field_size(
            send_ctx.largest_pn.as_ref(),
            truncated_pn,
            pn_length << 3,
        )?;
        trace!(
            "Here we finally got real {:?} packet number {}, largest_pn {:?}",
            level,
            real_pn,
            send_ctx.largest_pn
        );
        cursor.seek_relative(pn_length as i64)?;

        let decrypted_start_pos = cursor.position();
        let decrypted_end_pos = decrypted_start_pos + length - pn_length as u64;

        // Contruct aad from header protection
        let mut aad = vec![0u8; decrypted_start_pos as usize];
        aad.copy_from_slice(&cursor.get_ref()[..decrypted_start_pos as usize]);
        aad[0] = unprotected_flag;
        let pn_bytes = u32::to_be_bytes(truncated_pn);
        aad[packet_header_size as usize..packet_header_size as usize + pn_length as usize]
            .copy_from_slice(&pn_bytes[4 - pn_length as usize..]);

        let cipher_suite = match level {
            QuicLevel::Initial => TLS_AES_128_GCM_SHA256,
            QuicLevel::Handshake => qconn.tls.get_selected_cipher_suite()?,
            _ => unimplemented!(),
        };

        let decrypted_data = qconn.crypto.decrypt_packet(
            level,
            cipher_suite,
            &cursor.get_ref()[decrypted_start_pos as usize..decrypted_end_pos as usize],
            // The associated data, A, for the AEAD is the contents of the QUIC header,
            // starting from the first byte of either the short or long header,
            // up to and including the unprotected packet number.
            &aad,
            real_pn,
        )?;

        trace!(
            "Got level {:?} decrypted_data size {}",
            level,
            decrypted_data.len()
        );

        let lpkt = QuicLongHeaderPacket {
            packet_type: header_type,
            level,
            from: *source_addr,
            flag: unprotected_flag,
            pn: Some(real_pn),
            dcid,
            scid,
            length: Some(length),
            raw_payload: rcvbuf,
            payload: decrypted_data,
        };

        Ok((lpkt, consumed_size))
    }
}

fn encode_packet_number_field_size(
    packet_number: u64,
    lagest_acked: u64,
) -> Result<QuicPacketNumber> {
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-a.2

    let delta = packet_number.checked_sub(lagest_acked).ok_or_else(|| {
        anyhow!("Invalid packet_number {packet_number}, lagest_acked {lagest_acked}")
    })?;

    if delta <= 0x7f {
        Ok(QuicPacketNumber {
            packet_size: 1,
            truncated_pn: (packet_number & 0xff) as u32,
        })
    } else if delta <= 0x7fff {
        Ok(QuicPacketNumber {
            packet_size: 2,
            truncated_pn: (packet_number & 0xffff) as u32,
        })
    } else if delta <= 0x7fffff {
        Ok(QuicPacketNumber {
            packet_size: 3,
            truncated_pn: (packet_number & 0xffffff) as u32,
        })
    } else {
        Ok(QuicPacketNumber {
            packet_size: 4,
            truncated_pn: (packet_number & 0xffffffff) as u32,
        })
    }
}

fn decode_packet_number_field_size(
    largest_pn: Option<&u64>,
    truncated_pn: u32,
    pn_nbits: u8,
) -> Result<u64> {
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3
    let expected_pn = if let Some(lpn) = largest_pn {
        *lpn as i64 + 1
    } else {
        0
    };
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    trace!(
        "pn_nbits {}, pn_win {}, pn_hwin{}, pn_mask {}, expected_pn {}",
        pn_nbits,
        pn_win,
        pn_hwin,
        pn_mask,
        expected_pn
    );

    let candidate_pn = (expected_pn as u64 & (!pn_mask)) | truncated_pn as u64;

    // Expected_pn could be zero at the begining
    if candidate_pn as i64 <= expected_pn - pn_hwin as i64 && candidate_pn < (1u64 << 62) - pn_win {
        return Ok(candidate_pn + pn_win);
    }

    if candidate_pn > expected_pn as u64 + pn_hwin && candidate_pn >= pn_win {
        return Ok(candidate_pn - pn_win);
    }

    Ok(candidate_pn)
}

pub(crate) fn is_long_header(flag: u8) -> bool {
    flag & LONG_HEADER_FORM > 0
}
