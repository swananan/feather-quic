use anyhow::{anyhow, Result};
use byteorder::WriteBytesExt;
use std::io::{Cursor, Read, Seek, Write};
use tracing::{span, trace, Level};

use crate::connection::{QuicConnection, QuicLevel};
use crate::packet::QuicPacket;
use crate::send::QuicSendContext;
use crate::utils::{decode_variable_length, encode_variable_length, get_remain_length};

// The "Pkts" column in Table 3 lists the types of packets that each frame type could appear in,
// indicated by the following characters:
// I: Initial (Section 17.2.2)
// H: Handshake (Section 17.2.4)
// 0: 0-RTT (Section 17.2.3)
// 1: 1-RTT (Section 17.3.1)
// ih: Only a CONNECTION_CLOSE frame of type 0x1c can appear in Initial or Handshake packets.
//
// The "Spec" column in Table 3 summarizes any special rules governing the processing or generation of
// the frame type, as indicated by the following characters:
// N: Packets containing only frames with this marking are not ack-eliciting; see Section 13.2.
// C: Packets containing only frames with this marking do not count toward bytes in flight for congestion control purposes; see [QUIC-RECOVERY].
// P: Packets containing only frames with this marking can be used to probe new network paths during connection migration; see Section 9.1.
// F: The contents of frames with this marking are flow controlled; see Section 4.
#[derive(Debug)]
pub(crate) enum QuicFrameType {
    /// Pkts: IH01, Spec: NP
    Padding = 0x00,
    /// Pkts: IH01
    Ping = 0x01,
    /// Pkts: IH_1, Spec: NC
    Ack = 0x02,
    // TODO ack type 0x03
    /// Pkts: __01
    ResetStream = 0x04,
    /// Pkts: __01
    StopSending = 0x05,
    /// Pkts: IH_1
    Crypto = 0x06,
    /// Pkts: ___1
    NewToken = 0x07,
    /// Pkts: __01, Spec: F
    Stream = 0x08,
    /// Pkts: __01
    MaxData = 0x10,
    /// Pkts: __01
    MaxStreamData = 0x11,
    /// Pkts: __01
    MaxStreams = 0x12,
    /// Pkts: __01
    DataBlocked = 0x14,
    /// Pkts: __01
    StreamDataBlocked = 0x15,
    /// Pkts: __01
    StreamsBlocked = 0x16,
    /// Pkts: __01, Spec: P
    NewConnectionId = 0x18,
    /// Pkts: __01
    RetireConnectionId = 0x19,
    /// Pkts: __01, Spec: P
    PathChallenge = 0x1a,
    /// Pkts: ___1, Spec: P
    PathResponse = 0x1b,
    /// Pkts: ih01, Spec: N
    ConnectionClose = 0x1c,
    /// Pkts: ___1
    HandshakeDone = 0x1e,
}

impl From<u8> for QuicFrameType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => QuicFrameType::Padding,
            0x01 => QuicFrameType::Ping,
            0x02 => QuicFrameType::Ack,
            0x04 => QuicFrameType::ResetStream,
            0x05 => QuicFrameType::StopSending,
            0x06 => QuicFrameType::Crypto,
            0x07 => QuicFrameType::NewToken,
            0x08 => QuicFrameType::Stream,
            0x10 => QuicFrameType::MaxData,
            0x11 => QuicFrameType::MaxStreamData,
            0x12 => QuicFrameType::MaxStreams,
            0x14 => QuicFrameType::DataBlocked,
            0x15 => QuicFrameType::StreamDataBlocked,
            0x16 => QuicFrameType::StreamsBlocked,
            0x18 => QuicFrameType::NewConnectionId,
            0x19 => QuicFrameType::RetireConnectionId,
            0x1a => QuicFrameType::PathChallenge,
            0x1b => QuicFrameType::PathResponse,
            0x1c => QuicFrameType::ConnectionClose,
            0x1e => QuicFrameType::HandshakeDone,
            _ => panic!("Invalid QuicFrameType value"),
        }
    }
}

impl From<QuicFrameType> for u8 {
    fn from(val: QuicFrameType) -> Self {
        match val {
            QuicFrameType::Padding => 0x00,
            QuicFrameType::Ping => 0x01,
            QuicFrameType::Ack => 0x02,
            QuicFrameType::ResetStream => 0x04,
            QuicFrameType::StopSending => 0x05,
            QuicFrameType::Crypto => 0x06,
            QuicFrameType::NewToken => 0x07,
            QuicFrameType::Stream => 0x08,
            QuicFrameType::MaxData => 0x10,
            QuicFrameType::MaxStreamData => 0x11,
            QuicFrameType::MaxStreams => 0x12,
            QuicFrameType::DataBlocked => 0x14,
            QuicFrameType::StreamDataBlocked => 0x15,
            QuicFrameType::StreamsBlocked => 0x16,
            QuicFrameType::NewConnectionId => 0x18,
            QuicFrameType::RetireConnectionId => 0x19,
            QuicFrameType::PathChallenge => 0x1a,
            QuicFrameType::PathResponse => 0x1b,
            QuicFrameType::ConnectionClose => 0x1c,
            QuicFrameType::HandshakeDone => 0x1e,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Default)]
struct QuicHandshakeDone {
    common: QuicFrameCommon,
}

#[allow(dead_code)]
#[derive(Clone, Default)]
struct QuicPing {
    common: QuicFrameCommon,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicPadding {
    common: QuicFrameCommon,
    padding_size: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicAck {
    common: QuicFrameCommon,
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_range_count: u64,
    first_ack_range: u64,
    // ack_ranges: Option<Vec<QuicAckRange>>,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicResetStream {
    common: QuicFrameCommon,
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicStopSending {
    common: QuicFrameCommon,
    stream_id: u64,
    application_error_code: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicCrypto {
    common: QuicFrameCommon,
    offset: u64,
    crypto_data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicNewToken {
    common: QuicFrameCommon,
    token: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicStream {
    common: QuicFrameCommon,
    stream_id: u64,
    offset: u64,
    length: u64,
    is_fin: bool,
    stream_data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicMaxData {
    common: QuicFrameCommon,
    maximum_data: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicMaxStreamData {
    common: QuicFrameCommon,
    stream_id: u64,
    maximum_stream_data: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicMaxStreams {
    common: QuicFrameCommon,
    maximum_streams: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicDataBlocked {
    common: QuicFrameCommon,
    maximum_data: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicStreamDataBlocked {
    common: QuicFrameCommon,
    stream_id: u64,
    maximum_stream_data: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicStreamsBlocked {
    common: QuicFrameCommon,
    maximum_streams: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicNewConnectionId {
    common: QuicFrameCommon,
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: Vec<u8>,
    stateless_reset_token: [u8; 16],
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicRetireConnectionId {
    common: QuicFrameCommon,
    sequence_number: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicPathChallenge {
    common: QuicFrameCommon,
    data: [u8; 8],
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicPathResponse {
    common: QuicFrameCommon,
    data: [u8; 8],
}

#[allow(dead_code)]
#[derive(Clone)]
struct QuicConnectionClose {
    common: QuicFrameCommon,
    error_code: u64,
    frame_type: u64,
    reason: String,
}

#[allow(dead_code)]
#[derive(Clone, Default)]
struct QuicFrameCommon {
    is_key_updating: bool,
    level: Option<QuicLevel>,
    pn: Option<u64>,
}

#[allow(private_interfaces, dead_code)]
#[derive(Clone)]
pub(crate) enum QuicFrame {
    Padding(QuicPadding),
    Ping(QuicPing),
    Ack(QuicAck),
    ResetStream(QuicResetStream),
    StopSending(QuicStopSending),
    Crypto(QuicCrypto),
    NewToken(QuicNewToken),
    Stream(QuicStream),
    MaxData(QuicMaxData),
    MaxStreamData(QuicMaxStreamData),
    MaxStreams(QuicMaxStreams),
    DataBlocked(QuicDataBlocked),
    StreamDataBlocked(QuicStreamDataBlocked),
    StreamsBlocked(QuicStreamsBlocked),
    NewConnectionId(QuicNewConnectionId),
    RetireConnectionId(QuicRetireConnectionId),
    PathChallenge(QuicPathChallenge),
    PathResponse(QuicPathResponse),
    ConnectionClose(QuicConnectionClose),
    HandshakeDone(QuicHandshakeDone),
}

impl QuicFrame {
    pub(crate) fn serialize<W>(&self, cursor: &mut W, remain: u16) -> Result<bool>
    where
        W: Write + Seek + Read,
    {
        match self {
            QuicFrame::Crypto(crypto_frame) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
                // CRYPTO Frame {
                //   Type (i) = 0x06,
                //   Offset (i),
                //   Length (i),
                //   Crypto Data (..),
                // }

                // TODO: check it more accurate
                if remain < 10 + crypto_frame.crypto_data.len() as u16 {
                    return Ok(false);
                }

                let frame_type: u8 = QuicFrameType::Crypto.into();
                encode_variable_length(cursor, frame_type as u64)?;
                encode_variable_length(cursor, crypto_frame.offset)?;
                encode_variable_length(cursor, crypto_frame.crypto_data.len() as u64)?;
                cursor.write_all(&crypto_frame.crypto_data)?;
            }
            QuicFrame::Ping(_) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
                let frame_type: u8 = QuicFrameType::Ping.into();
                encode_variable_length(cursor, frame_type as u64)?;
            }
            _ => unimplemented!(),
        }

        Ok(true)
    }

    pub(crate) fn is_crypto_frame(&self) -> bool {
        matches!(self, QuicFrame::Crypto(_))
    }

    pub(crate) fn create_padding_frame<W>(cursor: &mut W, padding_frame_size: u16) -> Result<u32>
    where
        W: Write + Seek,
    {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1
        // PADDING Frame {
        //   Type (i) = 0x00,
        // }

        let cur_start = cursor.stream_position()?;
        cursor.write_u8(QuicFrameType::Padding.into())?;

        // Write padding bytes
        let padding_bytes = padding_frame_size
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Invalid padding frame size {}", padding_frame_size))?;

        cursor.write_all(&vec![0; padding_bytes as usize])?;

        let frame_size = cursor
            .stream_position()?
            .checked_sub(cur_start)
            .ok_or_else(|| {
                anyhow!(
                    "Invalid frame size calculation: start={}, end={}, padding={}",
                    cur_start,
                    cursor.stream_position().unwrap_or(0),
                    padding_frame_size
                )
            })?;

        trace!("Created PADDING frame of {} bytes", frame_size);
        Ok(frame_size as u32)
    }

    pub(crate) fn create_crypto_frame(
        send_ctx: &mut QuicSendContext,
        crypto_data: Vec<u8>,
    ) -> Result<Option<QuicFrame>> {
        let offset = send_ctx.crypto_send_offset;
        send_ctx.crypto_send_offset += crypto_data.len() as u64;

        let crypto_frame = QuicFrame::Crypto(QuicCrypto {
            common: QuicFrameCommon::default(),
            offset,
            crypto_data,
        });

        trace!(
            "Now we are creating Crypto frame, offset {}, length {}",
            offset,
            send_ctx.crypto_send_offset
        );

        Ok(Some(crypto_frame))
    }

    pub(crate) fn handle_quic_frame(qconn: &mut QuicConnection, pkt: &QuicPacket) -> Result<()> {
        let span = span!(
            Level::TRACE,
            "handle_quic_frame",
            level = ?pkt.get_packet_level(),
            payload_len = ?pkt.get_payload().len()
        );
        let _enter = span.enter();

        let level = pkt.get_packet_level();
        let pbuf = pkt.get_payload();
        let mut cursor = Cursor::new(pbuf);

        while (cursor.position() as usize) < pbuf.len() {
            let frame_type_val = decode_variable_length(&mut cursor)?;
            let frame_type = QuicFrameType::from(frame_type_val as u8);
            trace!(
                "Start to process QUIC frame {:?}, offset {}, frame_type {:?}, frame_type_val {}",
                level,
                cursor.position(),
                frame_type,
                frame_type_val
            );
            match frame_type {
                QuicFrameType::Crypto => Self::handle_crypto_frame(&mut cursor, qconn, level)?,
                _ => unimplemented!(),
            }
            trace!(
                "Handle QUIC frame with offset {}, udp datagram size {}",
                cursor.position(),
                pbuf.len()
            );
        }

        Ok(())
    }

    fn handle_crypto_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        let offset = decode_variable_length(cursor)?;
        let length = decode_variable_length(cursor)?;

        trace!(
            "Processing CRYPTO frame: level={:?}, offset={}, length={}",
            level,
            offset,
            length
        );

        let send_ctx = match level {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        // Verify frame ordering
        if send_ctx.crypto_recv_offset != offset {
            trace!(
                "Out-of-order CRYPTO frame: expected offset={}, got={}",
                send_ctx.crypto_recv_offset,
                offset
            );
            // TODO: handle reordered crypto frames
            unimplemented!();
        }

        let remain_bytes = get_remain_length(cursor).ok_or_else(|| {
            anyhow!(
                "Bad cursor, position {}, all size {}",
                cursor.position(),
                cursor.get_ref().len()
            )
        })?;

        if length > remain_bytes {
            return Err(anyhow!(
                "Invalid QUIC crypto frame, bad length {}, remain bytes {}",
                length,
                remain_bytes
            ));
        }

        send_ctx.crypto_recv_offset += length;

        let crypto_start_pos = cursor.position();

        // Tls module must consume all the crypto buffer
        qconn.tls.continue_tls_handshake(
            &cursor.get_ref()
                [crypto_start_pos as usize..crypto_start_pos as usize + length as usize],
            length,
        )?;
        cursor.seek_relative(length as i64)?;

        qconn.consume_tls_send_queue()?;

        Ok(())
    }
}
