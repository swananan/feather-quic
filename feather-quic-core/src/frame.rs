use anyhow::{anyhow, Result};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::{Cursor, Read, Seek, Write};
use std::ops::Div;
use std::time::{Duration, Instant};
use tracing::{error, info, info_span, span, trace, trace_span, warn, Level};

use crate::ack::QuicAckRange;
use crate::connection::{QuicConnection, QuicLevel};
use crate::error_code::QuicConnectionErrorCode;
use crate::packet::QuicPacket;
use crate::utils::{
    decode_variable_length, encode_variable_length, encode_variable_length_force_two_bytes,
    remaining_bytes,
};

const QUIC_CRYPTO_FRAME_MAX_BUFFER_SIZE: u64 = 1 << 16;
const QUIC_STATELESS_RESET_TOKEN_LENGTH: u16 = 16;

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
    /// Pkts: IH_1, Spec: NC
    AckEcn = 0x03,
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
            0x03 => QuicFrameType::AckEcn,
            0x04 => QuicFrameType::ResetStream,
            0x05 => QuicFrameType::StopSending,
            0x06 => QuicFrameType::Crypto,
            0x07 => QuicFrameType::NewToken,
            0x08..=0x0f => QuicFrameType::Stream,
            0x10 => QuicFrameType::MaxData,
            0x11 => QuicFrameType::MaxStreamData,
            0x12..=0x13 => QuicFrameType::MaxStreams,
            0x14 => QuicFrameType::DataBlocked,
            0x15 => QuicFrameType::StreamDataBlocked,
            0x16..=0x17 => QuicFrameType::StreamsBlocked,
            0x18 => QuicFrameType::NewConnectionId,
            0x19 => QuicFrameType::RetireConnectionId,
            0x1a => QuicFrameType::PathChallenge,
            0x1b => QuicFrameType::PathResponse,
            0x1c..=0x1d => QuicFrameType::ConnectionClose,
            0x1e => QuicFrameType::HandshakeDone,
            _ => panic!("Invalid QuicFrameType value {value:x}"),
        }
    }
}

impl From<QuicFrameType> for u8 {
    fn from(val: QuicFrameType) -> Self {
        match val {
            QuicFrameType::Padding => 0x00,
            QuicFrameType::Ping => 0x01,
            QuicFrameType::Ack => 0x02,
            QuicFrameType::AckEcn => 0x03,
            QuicFrameType::ResetStream => 0x04,
            QuicFrameType::StopSending => 0x05,
            QuicFrameType::Crypto => 0x06,
            QuicFrameType::NewToken => 0x07,
            QuicFrameType::Stream => unreachable!(),
            QuicFrameType::MaxData => 0x10,
            QuicFrameType::MaxStreamData => 0x11,
            QuicFrameType::MaxStreams => unreachable!(),
            QuicFrameType::DataBlocked => 0x14,
            QuicFrameType::StreamDataBlocked => 0x15,
            QuicFrameType::StreamsBlocked => unreachable!(),
            QuicFrameType::NewConnectionId => 0x18,
            QuicFrameType::RetireConnectionId => 0x19,
            QuicFrameType::PathChallenge => 0x1a,
            QuicFrameType::PathResponse => 0x1b,
            QuicFrameType::ConnectionClose => 0x1c,
            QuicFrameType::HandshakeDone => 0x1e,
        }
    }
}

#[derive(Clone, Default, Debug)]
struct QuicHandshakeDone {
    common: QuicFrameCommon,
}

#[derive(Clone, Default, Debug)]
pub(crate) struct QuicPing {
    common: QuicFrameCommon,
}

#[derive(Clone, Debug)]
struct QuicPadding {
    common: QuicFrameCommon,
}

#[derive(Clone, Debug)]
pub(crate) struct QuicAck {
    common: QuicFrameCommon,
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_range_count: u64,
    first_ack_range: u64,
    ack_ranges: Option<VecDeque<QuicAckRange>>,
}

impl QuicAck {
    #[allow(dead_code)]
    pub(crate) fn new(
        largest_acknowledged: u64,
        ack_delay: u64,
        ack_range_count: u64,
        first_ack_range: u64,
        ack_ranges: Option<VecDeque<QuicAckRange>>,
    ) -> Self {
        Self {
            largest_acknowledged,
            ack_range_count,
            ack_delay,
            first_ack_range,
            ack_ranges,
            common: QuicFrameCommon::default(),
        }
    }

    pub(crate) fn get_largest_acknowledged(&self) -> u64 {
        self.largest_acknowledged
    }
}

#[derive(Clone, Debug)]
pub(crate) struct QuicResetStream {
    common: QuicFrameCommon,
    pub(crate) stream_id: u64,
    pub(crate) application_error_code: u64,
    pub(crate) final_size: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct QuicStopSending {
    common: QuicFrameCommon,
    pub(crate) stream_id: u64,
    application_error_code: u64,
}

#[derive(Clone, Debug)]
struct QuicCrypto {
    common: QuicFrameCommon,
    offset: u64,
    crypto_data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicNewToken {
    common: QuicFrameCommon,
    token: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct QuicStreamFrame {
    common: QuicFrameCommon,
    pub(crate) stream_id: u64,
    pub(crate) offset: u64,
    pub(crate) stream_data: Option<Vec<u8>>,
    pub(crate) length: u64,
    pub(crate) is_fin: bool,
}

#[derive(Clone, Debug)]
struct QuicMaxData {
    common: QuicFrameCommon,
    maximum_data: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct QuicMaxStreamData {
    common: QuicFrameCommon,
    pub(crate) stream_id: u64,
    maximum_stream_data: u64,
}

#[derive(Clone, Debug)]
struct QuicMaxStreams {
    common: QuicFrameCommon,
    maximum_streams: u64,
}

#[derive(Clone, Debug)]
struct QuicDataBlocked {
    common: QuicFrameCommon,
    maximum_data: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct QuicStreamDataBlocked {
    common: QuicFrameCommon,
    pub(crate) stream_id: u64,
    maximum_stream_data: u64,
}

#[derive(Clone, Debug)]
struct QuicStreamsBlocked {
    common: QuicFrameCommon,
    maximum_streams: u64,
    is_bidirectional: bool,
}

#[derive(Clone, Debug)]
struct QuicNewConnectionId {
    common: QuicFrameCommon,
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: Vec<u8>,
    stateless_reset_token: [u8; 16],
}

#[derive(Clone, Debug)]
struct QuicRetireConnectionId {
    common: QuicFrameCommon,
    sequence_number: u64,
}

#[derive(Clone, Debug)]
struct QuicPathChallenge {
    common: QuicFrameCommon,
    data: [u8; 8],
}

#[derive(Clone, Debug)]
struct QuicPathResponse {
    common: QuicFrameCommon,
    data: [u8; 8],
}

#[derive(Clone, Debug)]
struct QuicConnectionClose {
    common: QuicFrameCommon,
    error_code: QuicConnectionErrorCode,
    reason: Option<String>,
}

#[derive(Clone, Default, Debug)]
struct QuicFrameCommon {
    pn: Option<u64>,
    send_time: Option<Instant>,
}

impl QuicFrameCommon {
    fn clear(&mut self) {
        self.send_time = None;
        self.pn = None;
    }
}

#[allow(private_interfaces, dead_code)]
#[derive(Clone, Debug)]
pub(crate) enum QuicFrame {
    Padding(QuicPadding),
    Ping(QuicPing),
    Ack(QuicAck),
    ResetStream(QuicResetStream),
    StopSending(QuicStopSending),
    Crypto(QuicCrypto),
    NewToken(QuicNewToken),
    Stream(QuicStreamFrame),
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
    pub(crate) fn serialize<W>(
        &mut self,
        cursor: &mut W,
        remain: u16,
    ) -> Result<(bool, Option<QuicFrame>)>
    where
        W: Write + Seek + Read,
    {
        let frame_type = match self {
            QuicFrame::Padding(_) => "PADDING",
            QuicFrame::Ping(_) => "PING",
            QuicFrame::Ack(_) => "ACK",
            QuicFrame::ResetStream(_) => "RESET_STREAM",
            QuicFrame::StopSending(_) => "STOP_SENDING",
            QuicFrame::Crypto(_) => "CRYPTO",
            QuicFrame::NewToken(_) => "NEW_TOKEN",
            QuicFrame::Stream(_) => "STREAM",
            QuicFrame::MaxData(_) => "MAX_DATA",
            QuicFrame::MaxStreamData(_) => "MAX_STREAM_DATA",
            QuicFrame::MaxStreams(_) => "MAX_STREAMS",
            QuicFrame::DataBlocked(_) => "DATA_BLOCKED",
            QuicFrame::StreamDataBlocked(_) => "STREAM_DATA_BLOCKED",
            QuicFrame::StreamsBlocked(_) => "STREAMS_BLOCKED",
            QuicFrame::NewConnectionId(_) => "NEW_CONNECTION_ID",
            QuicFrame::RetireConnectionId(_) => "RETIRE_CONNECTION_ID",
            QuicFrame::PathChallenge(_) => "PATH_CHALLENGE",
            QuicFrame::PathResponse(_) => "PATH_RESPONSE",
            QuicFrame::ConnectionClose(_) => "CONNECTION_CLOSE",
            QuicFrame::HandshakeDone(_) => "HANDSHAKE_DONE",
        };
        let _span = trace_span!("serialize_frame", frame_type = frame_type).entered();

        const MAX_VARIABLE_FIELD_SIZE: u16 = 8;
        match self {
            QuicFrame::Ack(ack_frame) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
                // ACK Frame {
                //   Type (i) = 0x02..0x03,
                //   Largest Acknowledged (i),
                //   ACK Delay (i),
                //   ACK Range Count (i),
                //   First ACK Range (i),
                //   ACK Range (..) ...,
                //   [ECN Counts (..)],
                // }

                if remain < 5 * MAX_VARIABLE_FIELD_SIZE {
                    warn!(
                        "Should provide more buffer for Ack frame, only got {} bytes",
                        remain
                    );
                    return Ok((false, None));
                }

                let frame_type: u8 = QuicFrameType::Ack.into();
                let start_pos = cursor.stream_position()?;
                encode_variable_length(cursor, frame_type as u64)?;
                encode_variable_length(cursor, ack_frame.largest_acknowledged)?;
                encode_variable_length(cursor, ack_frame.ack_delay)?;
                let consumed_size = cursor.stream_position()?.saturating_sub(start_pos);

                let remain_bytes = (remain as u64).saturating_sub(consumed_size);
                let range_count = remain_bytes
                    .saturating_sub(2 * MAX_VARIABLE_FIELD_SIZE as u64)
                    .div(2 * MAX_VARIABLE_FIELD_SIZE as u64);
                let ack_range_count = if range_count < ack_frame.ack_range_count {
                    warn!(
                        "remain_bytes {} is not enough, ack_range_count is {}, but \
                        only {} ranges can be added",
                        remain_bytes, ack_frame.ack_range_count, range_count
                    );
                    range_count
                } else {
                    ack_frame.ack_range_count
                };

                encode_variable_length(cursor, ack_range_count)?;
                encode_variable_length(cursor, ack_frame.first_ack_range)?;
                if let Some(ranges) = ack_frame.ack_ranges.as_ref() {
                    ranges.iter().take(range_count as usize).try_for_each(
                        |r| -> Result<(), anyhow::Error> {
                            encode_variable_length(cursor, r.get_gap())?;
                            encode_variable_length(cursor, r.get_ack_range_length())?;
                            Ok(())
                        },
                    )?;
                }

                trace!("Serialized {:?} frame", ack_frame);
            }
            QuicFrame::Crypto(crypto_frame) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
                // CRYPTO Frame {
                //   Type (i) = 0x06,
                //   Offset (i),
                //   Length (i),
                //   Crypto Data (..),
                // }

                if remain < 3 * MAX_VARIABLE_FIELD_SIZE {
                    return Ok((false, None));
                }

                let start_pos = cursor.stream_position()?;
                let frame_type: u8 = QuicFrameType::Crypto.into();
                encode_variable_length(cursor, frame_type as u64)?;
                encode_variable_length(cursor, crypto_frame.offset)?;
                let consumed_size = cursor.stream_position()?.saturating_sub(start_pos);
                let remain_bytes = (remain as u64).saturating_sub(consumed_size);
                let writen_len = if (remain_bytes as usize) < crypto_frame.crypto_data.len() {
                    remain_bytes as usize
                } else {
                    crypto_frame.crypto_data.len()
                };

                encode_variable_length(cursor, writen_len as u64)?;
                cursor.write_all(&crypto_frame.crypto_data[0..writen_len])?;
                if writen_len != crypto_frame.crypto_data.len() {
                    assert!(writen_len < crypto_frame.crypto_data.len());
                    info!(
                        "Have to split the crypto frame, origin len {}, consumed {} bytes",
                        crypto_frame.crypto_data.len(),
                        writen_len
                    );
                    let new_data = crypto_frame.crypto_data.split_off(writen_len);
                    let new_frame = QuicFrame::create_crypto_frame(
                        crypto_frame.offset + writen_len as u64,
                        new_data,
                    );
                    return Ok((true, Some(new_frame)));
                }

                trace!("Serialized {:?} frame, len {}", crypto_frame, writen_len);
            }
            QuicFrame::Ping(_) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
                let frame_type: u8 = QuicFrameType::Ping.into();
                encode_variable_length(cursor, frame_type as u64)?;

                trace!("Serialized {:?} frame", QuicFrameType::Ping);
            }
            QuicFrame::Stream(stream_frame) => {
                if remain < 4 * MAX_VARIABLE_FIELD_SIZE {
                    return Ok((false, None));
                }
                /* split frame if need */
                let mut type_bits: u8 = 0x08;
                if stream_frame.is_fin {
                    type_bits |= 0x01;
                }

                // Add length field no matter what
                type_bits |= 0x02;
                if stream_frame.offset > 0 {
                    type_bits |= 0x04;
                }

                trace!(
                    "Quic Stream Frame type_bits: 0x{:x}, stream_id: {}, offset: {}, \
                    length: {}, remain_bytes {}",
                    type_bits,
                    stream_frame.stream_id,
                    stream_frame.offset,
                    stream_frame.length,
                    remain,
                );
                let start_pos = cursor.stream_position()?;
                encode_variable_length(cursor, type_bits as u64)?;
                encode_variable_length(cursor, stream_frame.stream_id)?;
                if stream_frame.offset > 0 {
                    encode_variable_length(cursor, stream_frame.offset)?;
                }
                let consumed_size = cursor.stream_position()?.saturating_sub(start_pos);
                let remain_bytes = (remain as u64)
                    .saturating_sub(consumed_size + 2 /* size of length field */);
                let writen_len = if remain_bytes < stream_frame.length {
                    remain_bytes
                } else {
                    stream_frame.length
                };
                // Still need length field, if there are some upcoming stream frames in this
                // datagram
                encode_variable_length_force_two_bytes(cursor, writen_len)?;
                if writen_len > 0 {
                    cursor.write_all(
                        &stream_frame.stream_data.as_ref().unwrap()[0..writen_len as usize],
                    )?;
                    if writen_len != stream_frame.length {
                        assert!(writen_len < stream_frame.length);
                        info!(
                            "Have to split the stream frame, origin len {}, consumed {} bytes",
                            stream_frame.length, writen_len
                        );
                        let new_data = stream_frame
                            .stream_data
                            .as_mut()
                            .unwrap()
                            .split_off(writen_len as usize);
                        let new_len = new_data.len() as u64;
                        stream_frame.length = writen_len;
                        let new_frame = QuicFrame::create_stream_frame(
                            Some(new_data),
                            stream_frame.offset + writen_len,
                            stream_frame.stream_id,
                            stream_frame.is_fin,
                            new_len,
                        );
                        return Ok((true, Some(new_frame)));
                    }
                }

                trace!("Serialized {:?} frame", stream_frame);
            }
            QuicFrame::ResetStream(frame) => {
                if remain < 4 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }

                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::ResetStream) as u64,
                )?;
                encode_variable_length(cursor, frame.stream_id)?;
                encode_variable_length(cursor, frame.application_error_code)?;
                encode_variable_length(cursor, frame.final_size)?;
            }
            QuicFrame::StopSending(frame) => {
                if remain < 3 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::StopSending) as u64,
                )?;
                encode_variable_length(cursor, frame.stream_id)?;
                encode_variable_length(cursor, frame.application_error_code)?;
            }
            QuicFrame::MaxData(frame) => {
                if remain < 2 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(cursor, Into::<u8>::into(QuicFrameType::MaxData) as u64)?;
                encode_variable_length(cursor, frame.maximum_data)?;
            }
            QuicFrame::MaxStreamData(frame) => {
                if remain < 3 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::MaxStreamData) as u64,
                )?;
                encode_variable_length(cursor, frame.stream_id)?;
                encode_variable_length(cursor, frame.maximum_stream_data)?;
            }
            QuicFrame::MaxStreams(frame) => {
                if remain < 2 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(cursor, Into::<u8>::into(QuicFrameType::MaxStreams) as u64)?;
                encode_variable_length(cursor, frame.maximum_streams)?;
            }
            QuicFrame::DataBlocked(frame) => {
                if remain < 2 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::DataBlocked) as u64,
                )?;
                encode_variable_length(cursor, frame.maximum_data)?;
            }
            QuicFrame::StreamDataBlocked(frame) => {
                if remain < 3 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::StreamDataBlocked) as u64,
                )?;
                encode_variable_length(cursor, frame.stream_id)?;
                encode_variable_length(cursor, frame.maximum_stream_data)?;
            }
            QuicFrame::StreamsBlocked(frame) => {
                if remain < 2 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(cursor, if frame.is_bidirectional { 0x16 } else { 0x17 })?;
                encode_variable_length(cursor, frame.maximum_streams)?;
            }
            QuicFrame::ConnectionClose(frame) => {
                if remain
                    < 4 * MAX_VARIABLE_FIELD_SIZE
                        + frame.reason.as_ref().map(|s| s.len() as u16).unwrap_or(0)
                {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                match frame.error_code {
                    QuicConnectionErrorCode::TransportErrorCode((error_code, frame_type)) => {
                        encode_variable_length(cursor, 0x1c)?;
                        encode_variable_length(cursor, u64::from(error_code))?;
                        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19-6.4.1
                        encode_variable_length(cursor, frame_type.unwrap_or(0))?;
                    }
                    QuicConnectionErrorCode::ApplicationErrorCode(error_code) => {
                        encode_variable_length(cursor, 0x1d)?;
                        encode_variable_length(cursor, error_code)?;
                    }
                }

                if let Some(ref reason) = frame.reason {
                    encode_variable_length(cursor, reason.len() as u64)?;
                    cursor.write_all(reason.as_bytes())?;
                } else {
                    encode_variable_length(cursor, 0)?;
                }
            }
            QuicFrame::RetireConnectionId(frame) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
                // RETIRE_CONNECTION_ID Frame {
                //   Type (i) = 0x19,
                //   Sequence Number (i),
                // }
                if remain < 2 * MAX_VARIABLE_FIELD_SIZE {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::RetireConnectionId) as u64,
                )?;
                encode_variable_length(cursor, frame.sequence_number)?;
            }
            QuicFrame::PathChallenge(frame) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
                // PATH_CHALLENGE Frame {
                //   Type (i) = 0x1a,
                //   Data (64),
                // }
                if remain < 1 + 8 {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::PathChallenge) as u64,
                )?;
                cursor.write_all(&frame.data)?;
            }
            QuicFrame::PathResponse(frame) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.18
                // PATH_RESPONSE Frame {
                //   Type (i) = 0x1b,
                //   Data (64),
                // }
                if remain < 1 + 8 {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::PathResponse) as u64,
                )?;
                cursor.write_all(&frame.data)?;
            }
            QuicFrame::NewConnectionId(frame) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
                // NEW_CONNECTION_ID Frame {
                //   Type (i) = 0x18,
                //   Sequence Number (i),
                //   Retire Prior To (i),
                //   Length (8),
                //   Connection ID (8..160),
                //   Stateless Reset Token (128),
                // }
                if remain < 4 * MAX_VARIABLE_FIELD_SIZE + 1 + frame.connection_id.len() as u16 + 16
                {
                    trace!(
                        "Can not serialize the {:?}, since we only have {} bytes",
                        frame,
                        remain
                    );
                    return Ok((false, None));
                }
                trace!("Serialized {:?} frame", frame);
                encode_variable_length(
                    cursor,
                    Into::<u8>::into(QuicFrameType::NewConnectionId) as u64,
                )?;
                encode_variable_length(cursor, frame.sequence_number)?;
                encode_variable_length(cursor, frame.retire_prior_to)?;
                cursor.write_u8(frame.connection_id.len() as u8)?;
                cursor.write_all(&frame.connection_id)?;
                cursor.write_all(&frame.stateless_reset_token)?;
            }
            _ => unimplemented!("Not implemented frame type: {:?}", self),
        }

        Ok((true, None))
    }

    pub(crate) fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            QuicFrame::Ack(_) | QuicFrame::Padding(_) | QuicFrame::ConnectionClose(_)
        )
    }

    pub(crate) fn is_path_challenge_frame(&self) -> bool {
        matches!(self, QuicFrame::PathChallenge(_))
    }

    pub(crate) fn _is_crypto_frame(&self) -> bool {
        matches!(self, QuicFrame::Crypto(_))
    }

    pub(crate) fn get_send_time(&self) -> Option<Instant> {
        match self {
            QuicFrame::Padding(frame) => frame.common.send_time,
            QuicFrame::Ping(frame) => frame.common.send_time,
            QuicFrame::Ack(frame) => frame.common.send_time,
            QuicFrame::ResetStream(frame) => frame.common.send_time,
            QuicFrame::StopSending(frame) => frame.common.send_time,
            QuicFrame::Crypto(frame) => frame.common.send_time,
            QuicFrame::NewToken(frame) => frame.common.send_time,
            QuicFrame::Stream(frame) => frame.common.send_time,
            QuicFrame::MaxData(frame) => frame.common.send_time,
            QuicFrame::MaxStreamData(frame) => frame.common.send_time,
            QuicFrame::MaxStreams(frame) => frame.common.send_time,
            QuicFrame::DataBlocked(frame) => frame.common.send_time,
            QuicFrame::StreamDataBlocked(frame) => frame.common.send_time,
            QuicFrame::StreamsBlocked(frame) => frame.common.send_time,
            QuicFrame::NewConnectionId(frame) => frame.common.send_time,
            QuicFrame::RetireConnectionId(frame) => frame.common.send_time,
            QuicFrame::PathChallenge(frame) => frame.common.send_time,
            QuicFrame::PathResponse(frame) => frame.common.send_time,
            QuicFrame::ConnectionClose(frame) => frame.common.send_time,
            QuicFrame::HandshakeDone(frame) => frame.common.send_time,
        }
    }

    pub(crate) fn set_send_time(&mut self, send_time: Instant) {
        match self {
            QuicFrame::Padding(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::Ping(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::Ack(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::ResetStream(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::StopSending(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::Crypto(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::NewToken(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::Stream(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::MaxData(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::MaxStreamData(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::MaxStreams(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::DataBlocked(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::StreamDataBlocked(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::StreamsBlocked(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::NewConnectionId(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::RetireConnectionId(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::PathChallenge(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::PathResponse(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::ConnectionClose(frame) => frame.common.send_time = Some(send_time),
            QuicFrame::HandshakeDone(frame) => frame.common.send_time = Some(send_time),
        }
    }

    pub(crate) fn clear_frame_common(&mut self) {
        match self {
            QuicFrame::Padding(frame) => frame.common.clear(),
            QuicFrame::Ping(frame) => frame.common.clear(),
            QuicFrame::Ack(frame) => frame.common.clear(),
            QuicFrame::ResetStream(frame) => frame.common.clear(),
            QuicFrame::StopSending(frame) => frame.common.clear(),
            QuicFrame::Crypto(frame) => frame.common.clear(),
            QuicFrame::NewToken(frame) => frame.common.clear(),
            QuicFrame::Stream(frame) => frame.common.clear(),
            QuicFrame::MaxData(frame) => frame.common.clear(),
            QuicFrame::MaxStreamData(frame) => frame.common.clear(),
            QuicFrame::MaxStreams(frame) => frame.common.clear(),
            QuicFrame::DataBlocked(frame) => frame.common.clear(),
            QuicFrame::StreamDataBlocked(frame) => frame.common.clear(),
            QuicFrame::StreamsBlocked(frame) => frame.common.clear(),
            QuicFrame::NewConnectionId(frame) => frame.common.clear(),
            QuicFrame::RetireConnectionId(frame) => frame.common.clear(),
            QuicFrame::PathChallenge(frame) => frame.common.clear(),
            QuicFrame::PathResponse(frame) => frame.common.clear(),
            QuicFrame::ConnectionClose(frame) => frame.common.clear(),
            QuicFrame::HandshakeDone(frame) => frame.common.clear(),
        }
    }

    pub(crate) fn get_packet_number(&self) -> Option<u64> {
        match self {
            QuicFrame::Padding(frame) => frame.common.pn,
            QuicFrame::Ping(frame) => frame.common.pn,
            QuicFrame::Ack(frame) => frame.common.pn,
            QuicFrame::ResetStream(frame) => frame.common.pn,
            QuicFrame::StopSending(frame) => frame.common.pn,
            QuicFrame::Crypto(frame) => frame.common.pn,
            QuicFrame::NewToken(frame) => frame.common.pn,
            QuicFrame::Stream(frame) => frame.common.pn,
            QuicFrame::MaxData(frame) => frame.common.pn,
            QuicFrame::MaxStreamData(frame) => frame.common.pn,
            QuicFrame::MaxStreams(frame) => frame.common.pn,
            QuicFrame::DataBlocked(frame) => frame.common.pn,
            QuicFrame::StreamDataBlocked(frame) => frame.common.pn,
            QuicFrame::StreamsBlocked(frame) => frame.common.pn,
            QuicFrame::NewConnectionId(frame) => frame.common.pn,
            QuicFrame::RetireConnectionId(frame) => frame.common.pn,
            QuicFrame::PathChallenge(frame) => frame.common.pn,
            QuicFrame::PathResponse(frame) => frame.common.pn,
            QuicFrame::ConnectionClose(frame) => frame.common.pn,
            QuicFrame::HandshakeDone(frame) => frame.common.pn,
        }
    }

    pub(crate) fn set_packet_number(&mut self, pn: u64) {
        match self {
            QuicFrame::Padding(frame) => frame.common.pn = Some(pn),
            QuicFrame::Ping(frame) => frame.common.pn = Some(pn),
            QuicFrame::Ack(frame) => frame.common.pn = Some(pn),
            QuicFrame::ResetStream(frame) => frame.common.pn = Some(pn),
            QuicFrame::StopSending(frame) => frame.common.pn = Some(pn),
            QuicFrame::Crypto(frame) => frame.common.pn = Some(pn),
            QuicFrame::NewToken(frame) => frame.common.pn = Some(pn),
            QuicFrame::Stream(frame) => frame.common.pn = Some(pn),
            QuicFrame::MaxData(frame) => frame.common.pn = Some(pn),
            QuicFrame::MaxStreamData(frame) => frame.common.pn = Some(pn),
            QuicFrame::MaxStreams(frame) => frame.common.pn = Some(pn),
            QuicFrame::DataBlocked(frame) => frame.common.pn = Some(pn),
            QuicFrame::StreamDataBlocked(frame) => frame.common.pn = Some(pn),
            QuicFrame::StreamsBlocked(frame) => frame.common.pn = Some(pn),
            QuicFrame::NewConnectionId(frame) => frame.common.pn = Some(pn),
            QuicFrame::RetireConnectionId(frame) => frame.common.pn = Some(pn),
            QuicFrame::PathChallenge(frame) => frame.common.pn = Some(pn),
            QuicFrame::PathResponse(frame) => frame.common.pn = Some(pn),
            QuicFrame::ConnectionClose(frame) => frame.common.pn = Some(pn),
            QuicFrame::HandshakeDone(frame) => frame.common.pn = Some(pn),
        }
    }

    pub(crate) fn create_ack_frames(
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<VecDeque<QuicFrame>> {
        let mut ack_frames: VecDeque<QuicFrame> = VecDeque::new();
        if qconn.is_draining() {
            return Ok(ack_frames);
        }

        let send_ctx = match level {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        if let Some(single_pns) = send_ctx.get_single_ack_pns() {
            single_pns.iter().for_each(|pn| {
                ack_frames.push_back(QuicFrame::Ack(QuicAck {
                    common: QuicFrameCommon {
                        pn: None,
                        send_time: None,
                    },
                    largest_acknowledged: *pn,
                    ack_delay: 0, // Should be zero!
                    ack_range_count: 0,
                    first_ack_range: 0,
                    ack_ranges: None,
                }));
            });
        }

        if !send_ctx.need_ack(&qconn.current_ts, qconn.quic_config.get_max_ack_delay()) {
            return Ok(ack_frames);
        }

        let local_max_ack_delay =
            Duration::from_millis(qconn.quic_config.get_max_ack_delay() as u64);
        let ack_delay = qconn
            .current_ts
            .checked_duration_since(
                *send_ctx
                    .get_ack_delay_start_time()
                    .ok_or_else(|| anyhow!("Must have ack delay start time here"))?,
            )
            .map_or(0, |dur| {
                if dur >= local_max_ack_delay {
                    warn!("Ack delay {}ns could be a little high", dur.as_micros());
                    local_max_ack_delay.as_micros() as u64
                } else {
                    dur.as_micros() as u64
                }
            })
            .checked_mul(1 << qconn.quic_config.get_ack_delay_exponent())
            .ok_or_else(|| {
                anyhow!(
                    "Too big ack delay, exponent {}",
                    qconn.quic_config.get_ack_delay_exponent()
                )
            })?;

        let ranges = send_ctx.get_ranges();
        ack_frames.push_back(QuicFrame::Ack(QuicAck {
            common: QuicFrameCommon {
                pn: None,
                send_time: None,
            },
            largest_acknowledged: send_ctx
                .get_top_range()
                .ok_or_else(|| anyhow!("Must have top range"))?,
            ack_delay,
            ack_range_count: ranges.len() as u64,
            first_ack_range: send_ctx.get_first_range(),
            ack_ranges: Some(ranges),
        }));

        trace!(
            "Now we are creating {:?} ACK frames cnt {}, largest_pn {:?}",
            level,
            ack_frames.len(),
            send_ctx.largest_pn
        );

        send_ctx.reset_ack();
        qconn.reset_ack_delay_threshold();

        Ok(ack_frames)
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

    pub(crate) fn create_stop_sending_frame(
        stream_id: u64,
        application_error_code: u64,
    ) -> QuicFrame {
        let frame = QuicFrame::StopSending(QuicStopSending {
            common: QuicFrameCommon::default(),
            stream_id,
            application_error_code,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_streams_blocked_frame(
        maximum_streams: u64,
        is_bidirectional: bool,
    ) -> QuicFrame {
        let frame = QuicFrame::StreamsBlocked(QuicStreamsBlocked {
            common: QuicFrameCommon::default(),
            maximum_streams,
            is_bidirectional,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_data_blocked_frame(maximum_data: u64) -> QuicFrame {
        let frame = QuicFrame::DataBlocked(QuicDataBlocked {
            common: QuicFrameCommon::default(),
            maximum_data,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_stream_data_blocked_frame(
        stream_id: u64,
        maximum_stream_data: u64,
    ) -> QuicFrame {
        let frame = QuicFrame::StreamDataBlocked(QuicStreamDataBlocked {
            common: QuicFrameCommon::default(),
            stream_id,
            maximum_stream_data,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_max_data_frame(maximum_data: u64) -> QuicFrame {
        let frame = QuicFrame::MaxData(QuicMaxData {
            common: QuicFrameCommon::default(),
            maximum_data,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_max_stream_data_frame(
        stream_id: u64,
        maximum_stream_data: u64,
    ) -> QuicFrame {
        let frame = QuicFrame::MaxStreamData(QuicMaxStreamData {
            common: QuicFrameCommon::default(),
            stream_id,
            maximum_stream_data,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_reset_stream_frame(
        stream_id: u64,
        application_error_code: u64,
        final_size: u64,
    ) -> QuicFrame {
        let frame = QuicFrame::ResetStream(QuicResetStream {
            common: QuicFrameCommon::default(),
            stream_id,
            application_error_code,
            final_size,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_stream_frame(
        stream_data: Option<Vec<u8>>,
        offset: u64,
        stream_id: u64,
        is_fin: bool,
        length: u64,
    ) -> QuicFrame {
        trace!(
            "Now we are creating Stream frame, offset {}, data {:?}, fin flag {}",
            offset,
            stream_data,
            is_fin,
        );

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8-1
        QuicFrame::Stream(QuicStreamFrame {
            common: QuicFrameCommon::default(),
            offset,
            stream_id,
            stream_data,
            length,
            is_fin,
        })
    }

    pub(crate) fn create_connection_close_frame(
        error_code: QuicConnectionErrorCode,
        reason: Option<String>,
    ) -> QuicFrame {
        let frame = QuicFrame::ConnectionClose(QuicConnectionClose {
            common: QuicFrameCommon::default(),
            error_code,
            reason,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_crypto_frame(offset: u64, crypto_data: Vec<u8>) -> QuicFrame {
        trace!(
            "Now we are creating Crypto frame, offset {}, length {}",
            offset,
            crypto_data.len(),
        );

        QuicFrame::Crypto(QuicCrypto {
            common: QuicFrameCommon::default(),
            offset,
            crypto_data,
        })
    }

    pub(crate) fn handle_quic_frame(qconn: &mut QuicConnection, pkt: &QuicPacket) -> Result<bool> {
        let span = span!(
            Level::TRACE,
            "quic_frame",
            level = ?pkt.get_packet_level(),
            payload_size = pkt.get_payload().len(),
            frame_type = tracing::field::Empty,
            frame_type_val = tracing::field::Empty,
            pn = pkt.get_packet_number(),
        );
        let _enter = span.enter();

        let level = pkt.get_packet_level();
        let pbuf = pkt.get_payload();
        let mut cursor = Cursor::new(pbuf);

        let mut need_ack = false;
        while (cursor.position() as usize) < pbuf.len() {
            let frame_type_val = decode_variable_length(&mut cursor)?;
            let frame_type = QuicFrameType::from(frame_type_val as u8);

            span.record("frame_type", format!("{frame_type:?}"));
            trace!(
                "Start to process QUIC frame {:?}, offset {}, frame_type {:?}, frame_type_val {}",
                level,
                cursor.position(),
                frame_type,
                frame_type_val
            );
            match frame_type {
                QuicFrameType::Crypto => Self::handle_crypto_frame(&mut cursor, qconn, level)?,
                QuicFrameType::Ack => Self::handle_ack_frame(&mut cursor, qconn, level)?,
                QuicFrameType::Ping => Self::handle_ping_frame(&mut cursor, qconn, level)?,
                QuicFrameType::Padding => Self::handle_padding_frame(&mut cursor, qconn, level)?,
                QuicFrameType::HandshakeDone => {
                    Self::handle_handshake_done_frame(&mut cursor, qconn, level)?
                }
                QuicFrameType::NewConnectionId => {
                    Self::handle_new_conncetion_id_frame(&mut cursor, qconn, level)?
                }
                QuicFrameType::RetireConnectionId => {
                    Self::handle_retire_connection_id_frame(&mut cursor, qconn, level)?
                }
                QuicFrameType::PathChallenge => {
                    Self::handle_path_challenge_frame(&mut cursor, qconn, level)?
                }
                QuicFrameType::PathResponse => {
                    Self::handle_path_response_frame(&mut cursor, qconn, level)?
                }
                QuicFrameType::NewToken => Self::handle_new_token_frame(&mut cursor, qconn, level)?,
                QuicFrameType::Stream => {
                    span.record("frame_type_val", format!("0x{frame_type_val:x}"));
                    Self::handle_stream_frame(&mut cursor, qconn, frame_type_val)?
                }
                QuicFrameType::ResetStream => Self::handle_reset_stream_frame(&mut cursor, qconn)?,
                QuicFrameType::StopSending => Self::handle_stop_sending_frame(&mut cursor, qconn)?,
                QuicFrameType::MaxStreams => {
                    Self::handle_max_streams_frame(&mut cursor, qconn, frame_type_val)?
                }
                QuicFrameType::MaxData => Self::handle_max_data_frame(&mut cursor, qconn)?,
                QuicFrameType::MaxStreamData => {
                    Self::handle_max_stream_data_frame(&mut cursor, qconn)?
                }
                QuicFrameType::StreamsBlocked => {
                    Self::handle_streams_blocked_frame(&mut cursor, qconn, frame_type_val)?
                }
                QuicFrameType::DataBlocked => Self::handle_data_blocked_frame(&mut cursor, qconn)?,
                QuicFrameType::StreamDataBlocked => {
                    Self::handle_stream_data_blocked_frame(&mut cursor, qconn)?
                }
                QuicFrameType::ConnectionClose => {
                    Self::handle_connection_close_frame(&mut cursor, qconn, frame_type_val, level)?
                }
                _ => unimplemented!(),
            }

            if Self::is_ack_eliciting_by_frame_type(frame_type) {
                need_ack = true;
            }

            trace!(
                "Handle QUIC frame with offset {}, udp datagram size {}",
                cursor.position(),
                pbuf.len(),
            );
        }

        Ok(need_ack)
    }

    fn is_ack_eliciting_by_frame_type(ft: QuicFrameType) -> bool {
        !matches!(
            ft,
            QuicFrameType::Ack | QuicFrameType::Padding | QuicFrameType::ConnectionClose
        )
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

        let remain_bytes = remaining_bytes(cursor)?;
        if length > remain_bytes {
            return Err(anyhow!(
                "Invalid QUIC crypto frame, bad length {}, remain bytes {}",
                length,
                remain_bytes
            ));
        }

        let crypto_start_pos = cursor.position();

        let send_ctx = match level {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        // Verify frame ordering
        match send_ctx.crypto_recv_offset.cmp(&offset) {
            Ordering::Less => {
                trace!(
                    "Out-of-order CRYPTO frame: expected offset={}, got={}",
                    send_ctx.crypto_recv_offset,
                    offset
                );
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-7.5
                if send_ctx.get_crypto_recv_cbufs_length() + length
                    > QUIC_CRYPTO_FRAME_MAX_BUFFER_SIZE
                {
                    // Create crypto buffer exceeded error and throw it
                    let connection_error =
                        crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                            u64::from(crate::error_code::TransportErrorCode::CryptoBufferExceeded),
                            Some(QuicFrameType::Crypto as u64), // CRYPTO frame type
                        );
                    return Err(anyhow::Error::from(connection_error));
                }
                send_ctx.insert_crypto_recv_cbufs(
                    &cursor.get_ref()
                        [crypto_start_pos as usize..crypto_start_pos as usize + length as usize],
                    offset,
                );
                cursor.seek_relative(length as i64)?;
                return Ok(());
            }
            Ordering::Greater => {
                info!(
                    "Out-of-order CRYPTO frame has been received: expected offset={}, got={}",
                    send_ctx.crypto_recv_offset, offset
                );

                // https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.3
                cursor.seek_relative(length as i64)?;
                send_ctx.resend_all()?;
                qconn.set_next_send_event_time(0);

                return Ok(());
            }
            _ => (),
        }

        send_ctx.crypto_recv_offset += length;

        // Tls module must consume all the crypto buffer
        let tls_result = qconn.tls.handle_tls_handshake(
            &cursor.get_ref()
                [crypto_start_pos as usize..crypto_start_pos as usize + length as usize],
        );

        // Handle TLS errors
        if let Err(e) = tls_result {
            return Self::handle_tls_handshake_error(qconn, e);
        }

        cursor.seek_relative(length as i64)?;

        if let Some(pre_buf) = send_ctx.consume_next_recv_cbufs(offset + length) {
            trace!(
                "Continue to consume pre restored crypto bufs, offset {}, length {}, crypto_recv_offset {}",
                offset + length,
                pre_buf.len(),
                send_ctx.crypto_recv_offset,
            );

            // Handle buffered data
            let tls_result = qconn.tls.handle_tls_handshake(&pre_buf);

            // Handle TLS errors for buffered data
            if let Err(e) = tls_result {
                return Self::handle_tls_handshake_error(qconn, e);
            }

            send_ctx.crypto_recv_offset += pre_buf.len() as u64;
        }

        if qconn.tls.should_derive_hs_secret()
            && !qconn.crypto.is_key_available(QuicLevel::Handshake)
        {
            qconn.crypto.create_secrets(
                qconn.tls.get_selected_cipher_suite()?,
                QuicLevel::Handshake,
                qconn.tls.get_handshake_client_secret()?,
                qconn.tls.get_handshake_server_secret()?,
            )?;
        }

        if qconn.tls.should_derive_ap_secret()
            && !qconn.crypto.is_key_available(QuicLevel::Application)
        {
            qconn.crypto.create_secrets(
                qconn.tls.get_selected_cipher_suite()?,
                QuicLevel::Application,
                qconn.tls.get_application_client_secret()?,
                qconn.tls.get_application_server_secret()?,
            )?;
        }

        if qconn.tls.have_server_transport_params() {
            if let Err(e) = qconn.handle_encrypted_extensions() {
                // Convert generic error from handle_encrypted_extensions to transport parameter error
                error!("Transport parameter validation failed: {}", e);

                // Create transport parameter error with CRYPTO frame type
                let transport_param_error =
                    crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                        u64::from(crate::error_code::TransportErrorCode::TransportParameterError),
                        Some(QuicFrameType::Crypto as u64), // CRYPTO frame type
                    );

                return Err(anyhow::Error::from(transport_param_error));
            }

            if qconn.idle_timeout.is_none() {
                // Max_idle_timeout: Idle timeout is disabled when both endpoints
                // omit this transport parameter or specify a value of 0.
                let peer_idle_timeout = qconn.get_peer_max_idle_timeout().unwrap_or(0);
                let local_idle_timeout = qconn.quic_config.get_idle_timeout();

                qconn.idle_timeout = if local_idle_timeout == 0 {
                    Some(peer_idle_timeout)
                } else if peer_idle_timeout == 0 {
                    Some(local_idle_timeout)
                } else {
                    Some(local_idle_timeout.min(peer_idle_timeout))
                };

                info!(
                    "The real idle_timeout {} have been negotiated from local {} and peer {}",
                    qconn.idle_timeout.unwrap(),
                    local_idle_timeout,
                    peer_idle_timeout
                );
            }

            if qconn.rtt.max_ack_delay.is_none() {
                if let Some(mad) = qconn.get_peer_max_ack_delay() {
                    info!("Update max_ack_delay to {} from peer", mad);
                    qconn.rtt.max_ack_delay = Some(mad);
                }
            }

            if qconn.rtt.ack_delay_exponent.is_none() {
                if let Some(ade) = qconn.get_peer_ack_delay_exponent() {
                    info!("Update ack_delay_exponent to {} from peer", ade);
                    qconn.rtt.ack_delay_exponent = Some(ade);
                }
            }

            if !qconn.mtu.has_max_mtu() {
                let peer_mtu = qconn.get_peer_max_udp_payload_size().unwrap_or(0);
                let local_mtu = qconn.quic_config.get_max_udp_payload_size().unwrap_or(0);

                let final_mtu = if local_mtu > 0 && peer_mtu > 0 {
                    local_mtu.min(peer_mtu)
                } else {
                    local_mtu.max(peer_mtu)
                };

                info!(
                    "Update max_mtu to {} from peer {}, local {}",
                    final_mtu, peer_mtu, local_mtu
                );
                qconn.mtu.set_max_mtu(final_mtu);
            }
        }

        qconn.consume_tls_send_queue()?;

        Ok(())
    }

    // Helper function to handle TLS handshake errors
    fn handle_tls_handshake_error(_qconn: &mut QuicConnection, e: anyhow::Error) -> Result<()> {
        // Check for QuicConnectionErrorCode first
        if let Some(_connection_error) =
            e.downcast_ref::<crate::error_code::QuicConnectionErrorCode>()
        {
            // Already a QuicConnectionErrorCode, just re-throw it
            return Err(e);
        } else if let Some(tls_err) = e.downcast_ref::<crate::tls::TlsHandshakeError>() {
            let tls_error = tls_err.get_tls_error();

            // Convert TLS error to QuicConnectionErrorCode and throw it
            let connection_error =
                crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                    tls_error.to_quic_error_code(),
                    Some(QuicFrameType::Crypto as u64), // CRYPTO frame type
                );
            return Err(anyhow::Error::from(connection_error));
        }

        // For other errors, convert to generic transport error
        let transport_error =
            crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                u64::from(crate::error_code::TransportErrorCode::InternalError),
                Some(QuicFrameType::Crypto as u64),
            );
        Err(anyhow::Error::from(transport_error))
    }

    fn handle_reset_stream_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
        // RESET_STREAM Frame {
        //   Type (i) = 0x04,
        //   Stream ID (i),
        //   Application Protocol Error Code (i),
        //   Final Size (i),
        // }
        let span = info_span!("handle_reset_stream_frame");
        let _enter = span.enter();

        let stream_id = decode_variable_length(cursor)?;
        let application_error_code = decode_variable_length(cursor)?;
        let final_size = decode_variable_length(cursor)?;

        trace!(
            "Got reset stream frame, stream id {}, error code {}, final_size {}",
            stream_id,
            application_error_code,
            final_size,
        );

        qconn.handle_reset_stream_frame(stream_id, application_error_code, final_size)
    }

    fn handle_stop_sending_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
        // STOP_SENDING Frame {
        //   Type (i) = 0x05,
        //   Stream ID (i),
        //   Application Protocol Error Code (i),
        // }
        let stream_id = decode_variable_length(cursor)?;
        let application_error_code = decode_variable_length(cursor)?;

        trace!(
            "Got stop sending frame, stream id {}, error code {}",
            stream_id,
            application_error_code
        );

        qconn.handle_stop_sending_frame(stream_id, application_error_code)
    }

    fn handle_max_streams_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        frame_type: u64,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
        // MAX_STREAMS Frame {
        //   Type (i) = 0x12..0x13,
        //   Maximum Streams (i),
        // }
        let span = info_span!("handle_max_streams_frame", frame_type = ?frame_type);
        let _enter = span.enter();

        let is_bidirectional = if frame_type == 0x12 {
            true
        } else if frame_type == 0x13 {
            false
        } else {
            unreachable!("Invalid frame_type {}", frame_type);
        };
        let max_streams = decode_variable_length(cursor)?;

        trace!(
            "Got max streams frame, is_bidirectional {}, max_streams {}",
            is_bidirectional,
            max_streams
        );

        qconn.handle_max_streams_frame(is_bidirectional, max_streams)
    }

    fn handle_max_stream_data_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
        // MAX_STREAM_DATA Frame {
        //   Type (i) = 0x11,
        //   Stream ID (i),
        //   Maximum Stream Data (i),
        // }
        let stream_id = decode_variable_length(cursor)?;
        let maximum_stream_data = decode_variable_length(cursor)?;

        trace!(
            "Got max stream data frame, stream_id {}, maximum_stream_data {}",
            stream_id,
            maximum_stream_data
        );

        qconn.handle_max_stream_data_frame(stream_id, maximum_stream_data)
    }

    fn handle_streams_blocked_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        frame_type: u64,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14
        let maximum_streams = decode_variable_length(cursor)?;

        let is_bidirectional = if frame_type == 0x17 {
            false
        } else if frame_type == 0x16 {
            true
        } else {
            unreachable!("Invalid frame_type {}", frame_type);
        };
        trace!(
            "Got streams blocked frame, maximum_streams {}, is_bidirectional {}",
            maximum_streams,
            is_bidirectional
        );

        qconn.handle_streams_blocked_frame(maximum_streams, is_bidirectional)
    }

    fn handle_connection_close_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        frame_type: u64,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
        let error_code = decode_variable_length(cursor)?;

        let error_code = if frame_type == 0x1c {
            QuicConnectionErrorCode::create_transport_error_code(
                error_code,
                Some(decode_variable_length(cursor)?),
            )
        } else if frame_type == 0x1d {
            QuicConnectionErrorCode::create_application_error_code(error_code)
        } else {
            unreachable!("Invalid frame_type {}", frame_type);
        };

        let reason_len = decode_variable_length(cursor)?;
        let mut reason = vec![0u8; reason_len as usize];
        cursor.read_exact(&mut reason)?;
        let reason = String::from_utf8(reason)?;

        info!(
            "Got connection close frame, error_code {:?}, reason {}",
            error_code, reason,
        );

        qconn.handle_connection_close_frame(error_code, reason, level)
    }

    fn handle_data_blocked_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
        let span = info_span!("handle_data_blocked_frame");
        let _enter = span.enter();

        let maximum_data = decode_variable_length(cursor)?;

        trace!("Got data blocked frame, maximum_data {}", maximum_data);

        qconn.handle_data_blocked_frame(maximum_data)
    }

    fn handle_stream_data_blocked_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
        let stream_id = decode_variable_length(cursor)?;
        let maximum_stream_data = decode_variable_length(cursor)?;

        trace!(
            "Got stream data blocked frame, stream_id {}, maximum_stream_data {}",
            stream_id,
            maximum_stream_data
        );

        qconn.handle_stream_data_blocked_frame(stream_id, maximum_stream_data)
    }

    fn handle_max_data_frame(cursor: &mut Cursor<&[u8]>, qconn: &mut QuicConnection) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
        // MAX_DATA Frame {
        //   Type (i) = 0x10,
        //   Maximum Data (i),
        // }

        let span = info_span!("handle_max_data_frame");
        let _enter = span.enter();

        let maximum_data = decode_variable_length(cursor)?;

        trace!("Got max data frame, maximum_data {}", maximum_data);

        qconn.handle_max_data_frame(maximum_data)
    }

    fn handle_new_token_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
        // NEW_TOKEN Frame {
        //  Type (i) = 0x07,
        //  Token Length (i),
        //  Token (..),
        //}

        assert_eq!(level, QuicLevel::Application);

        let token_len = decode_variable_length(cursor)?;
        let mut token = vec![0u8; token_len as usize];
        cursor.read_exact(&mut token)?;

        trace!("Got new token {} bytes {:x?}", token_len, &token,);

        qconn.new_token = Some(token);

        Ok(())
    }

    fn handle_new_conncetion_id_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
        // NEW_CONNECTION_ID Frame {
        //   Type (i) = 0x18,
        //   Sequence Number (i),
        //   Retire Prior To (i),
        //   Length (8),
        //   Connection ID (8..160),
        //   Stateless Reset Token (128),
        // }

        assert_eq!(level, QuicLevel::Application);

        // The sequence number assigned to the connection ID by the sender,
        // encoded as a variable-length integer; see Section 5.1.1.
        let sequence_number = decode_variable_length(cursor)?;
        let retire_prior = decode_variable_length(cursor)?;

        let scid_len = cursor.read_u8()?;
        let mut scid = vec![0u8; scid_len as usize];
        cursor.read_exact(&mut scid)?;

        let mut stateless_reset_token = [0u8; QUIC_STATELESS_RESET_TOKEN_LENGTH as usize];
        cursor.read_exact(&mut stateless_reset_token)?;

        trace!(
            "Got new connection id {} bytes {:x?}, sequence_number {}, retire_prior {} \
            stateless reset token {:x?}",
            scid_len,
            scid,
            sequence_number,
            retire_prior,
            stateless_reset_token
        );

        // Handle the new connection ID and check for errors
        qconn.handle_new_conncetion_id_frame(
            sequence_number,
            retire_prior,
            &scid,
            &stateless_reset_token,
        )?;

        Ok(())
    }

    #[allow(unused_variables)]
    fn handle_handshake_done_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
        // HANDSHAKE_DONE Frame {
        //    Type (i) = 0x1e,
        // }

        assert_eq!(level, QuicLevel::Application);
        info!("Now we can say that QUIC handshake was performed perfectly!");

        qconn.set_connected()?;

        qconn
            .crypto
            .quic_secrets_update(qconn.tls.get_selected_cipher_suite()?)?;

        if qconn.quic_config.get_trigger_key_update().is_some() {
            QuicFrame::create_and_insert_ping_frame(qconn, QuicLevel::Application)?;
        }

        if qconn.crypto.is_key_available(QuicLevel::Handshake) {
            // https://www.rfc-editor.org/rfc/rfc9001#section-4.9.2
            qconn.discard_keys(QuicLevel::Handshake)?;
            qconn.hs_send.clear();
        }

        Ok(())
    }

    pub(crate) fn create_and_insert_ping_frame(
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        let send_ctx = match level {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        let ping_frame = QuicFrame::Ping(QuicPing::default());
        send_ctx.insert_send_queue_front(ping_frame);

        trace!("Created {:?} ping frame", level);

        Ok(())
    }

    #[allow(unused_variables)]
    fn handle_padding_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1

        // Padding frame doesn't have length field, but it must be the last QUIC frame in the packet
        // so we need to consume the entire cursor
        let remain_bytes = remaining_bytes(cursor)?;
        cursor.seek_relative(remain_bytes as i64)?;

        Ok(())
    }

    #[allow(unused_variables)]
    fn handle_ping_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
        // The receiver of a PING frame simply needs to acknowledge the packet containing this frame.
        // The PING frame can be used to keep a connection alive when an application or application
        // protocol wishes to prevent the connection from timing out; see Section 10.1.2.
        Ok(())
    }

    fn handle_stream_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        type_bits: u64,
    ) -> Result<()> {
        qconn.handle_stream_frame(cursor, type_bits)
    }

    fn handle_ack_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
        // ACK Frame {
        //   Type (i) = 0x02..0x03,
        //   Largest Acknowledged (i),
        //   ACK Delay (i),
        //   ACK Range Count (i),
        //   First ACK Range (i),
        //   ACK Range (..) ...,
        //   [ECN Counts (..)],
        // }
        let largest_acked = decode_variable_length(cursor)?;
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.5
        let ack_delay = decode_variable_length(cursor)?;
        let ack_range_count = decode_variable_length(cursor)?;
        let first_ack_range = decode_variable_length(cursor)?;

        let mut mtu_probe_pns = qconn.get_mtu_probe_pns();
        let send_ctx = match level {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        trace!(
            "Processing {:?} ack frame, we received largest_acked {}, ack_delay {}, \
            ack_range_count {}, first_ack_range {}, origin largest_acked {:?}",
            level,
            largest_acked,
            ack_delay,
            ack_range_count,
            first_ack_range,
            send_ctx.largest_acked,
        );

        // ACK Range {
        //   Gap (i),
        //   ACK Range Length (i),
        // }
        let mut ack_ranges = vec![];
        for _ in 0..ack_range_count {
            let gap = decode_variable_length(cursor)?;
            let ack_range_length = decode_variable_length(cursor)?;
            ack_ranges.push(QuicAckRange::new(gap, ack_range_length));
        }

        // TODO: Update Congestion Control state via ACK frame
        // https://www.rfc-editor.org/rfc/rfc9002.html#section-7

        // Clean the Acked frames in sent queue
        // and retire the old ack ranges in the ack generator
        let stream_frames = send_ctx.handle_ack_frame(
            first_ack_range,
            largest_acked,
            &ack_ranges,
            &mut qconn.rtt,
            &qconn.current_ts,
            ack_delay,
            mtu_probe_pns.as_mut(),
        )?;

        qconn.handle_acked_stream_frame(stream_frames)?;
        qconn.reset_pto_backoff_factor();
        qconn.detect_lost()?;
        qconn.set_loss_or_pto_timer()?;
        qconn.handle_acked_mtu_probe(mtu_probe_pns.as_ref())?;

        if !ack_ranges.is_empty() {
            trace!(
                "Processing ack frame, we received ack ranges {:?}",
                ack_ranges
            );
        }

        Ok(())
    }

    fn handle_path_challenge_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
        // PATH_CHALLENGE Frame {
        //   Type (i) = 0x1a,
        //   Data (64),
        // }
        if level != QuicLevel::Application {
            return Err(anyhow::anyhow!("Invalid level for path challenge frame"));
        }

        let mut data = [0u8; 8];
        cursor.read_exact(&mut data)?;

        // Delegate to connection-level handler which has access to migration detection logic
        qconn.handle_path_challenge_frame(data)
    }

    fn handle_path_response_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.18
        // PATH_RESPONSE Frame {
        //   Type (i) = 0x1b,
        //   Data (64),
        // }
        assert_eq!(level, QuicLevel::Application);

        let mut data = [0u8; 8];
        cursor.read_exact(&mut data)?;

        trace!("Got path response frame, data {:x?}", data);

        // Handle path response in connection context
        qconn.handle_path_response_frame(data)?;

        Ok(())
    }

    fn handle_retire_connection_id_frame(
        cursor: &mut Cursor<&[u8]>,
        qconn: &mut QuicConnection,
        level: QuicLevel,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
        // RETIRE_CONNECTION_ID Frame {
        //   Type (i) = 0x19,
        //   Sequence Number (i),
        // }
        assert_eq!(level, QuicLevel::Application);

        let sequence_number = decode_variable_length(cursor)?;

        trace!(
            "Got retire connection id frame, sequence_number {}",
            sequence_number
        );

        qconn.handle_retire_connection_id_frame(sequence_number)?;

        Ok(())
    }

    pub(crate) fn create_path_challenge_frame(data: [u8; 8]) -> QuicFrame {
        let frame = QuicFrame::PathChallenge(QuicPathChallenge {
            common: QuicFrameCommon::default(),
            data,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_path_response_frame(data: [u8; 8]) -> QuicFrame {
        let frame = QuicFrame::PathResponse(QuicPathResponse {
            common: QuicFrameCommon::default(),
            data,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_retire_connection_id_frame(sequence_number: u64) -> QuicFrame {
        let frame = QuicFrame::RetireConnectionId(QuicRetireConnectionId {
            common: QuicFrameCommon::default(),
            sequence_number,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }

    pub(crate) fn create_new_connection_id_frame(
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: &[u8],
        stateless_reset_token: &[u8; 16],
    ) -> QuicFrame {
        let frame = QuicFrame::NewConnectionId(QuicNewConnectionId {
            common: QuicFrameCommon::default(),
            sequence_number,
            retire_prior_to,
            connection_id: connection_id.to_vec(),
            stateless_reset_token: *stateless_reset_token,
        });

        trace!("Now we are creating {:?} frame", frame);

        frame
    }
}
