use anyhow::{anyhow, Result};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::{Cursor, Read, Seek, Write};
use std::ops::Div;
use std::time::{Duration, Instant};
use tracing::{info, span, trace, warn, Level};

use crate::ack::QuicAckRange;
use crate::connection::{QuicConnection, QuicLevel};
use crate::packet::QuicPacket;
use crate::send::QuicSendContext;
use crate::utils::{decode_variable_length, encode_variable_length, remaining_bytes};

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
    /// Pkts: ih01, Spec: N
    AppConnectionClose = 0x1d,
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
            0x12 => QuicFrameType::MaxStreams,
            0x14 => QuicFrameType::DataBlocked,
            0x15 => QuicFrameType::StreamDataBlocked,
            0x16 => QuicFrameType::StreamsBlocked,
            0x18 => QuicFrameType::NewConnectionId,
            0x19 => QuicFrameType::RetireConnectionId,
            0x1a => QuicFrameType::PathChallenge,
            0x1b => QuicFrameType::PathResponse,
            0x1c => QuicFrameType::ConnectionClose,
            0x1d => QuicFrameType::AppConnectionClose,
            0x1e => QuicFrameType::HandshakeDone,
            _ => panic!("Invalid QuicFrameType value {:x}", value),
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
            QuicFrameType::AppConnectionClose => 0x1d,
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

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicPadding {
    common: QuicFrameCommon,
    padding_size: u64,
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

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicResetStream {
    common: QuicFrameCommon,
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicStopSending {
    common: QuicFrameCommon,
    stream_id: u64,
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

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct QuicStream {
    common: QuicFrameCommon,
    stream_id: u64,
    offset: u64,
    length: u64,
    is_fin: bool,
    stream_data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicMaxData {
    common: QuicFrameCommon,
    maximum_data: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicMaxStreamData {
    common: QuicFrameCommon,
    stream_id: u64,
    maximum_stream_data: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicMaxStreams {
    common: QuicFrameCommon,
    maximum_streams: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicDataBlocked {
    common: QuicFrameCommon,
    maximum_data: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicStreamDataBlocked {
    common: QuicFrameCommon,
    stream_id: u64,
    maximum_stream_data: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicStreamsBlocked {
    common: QuicFrameCommon,
    maximum_streams: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicNewConnectionId {
    common: QuicFrameCommon,
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: Vec<u8>,
    stateless_reset_token: [u8; 16],
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicRetireConnectionId {
    common: QuicFrameCommon,
    sequence_number: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicPathChallenge {
    common: QuicFrameCommon,
    data: [u8; 8],
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicPathResponse {
    common: QuicFrameCommon,
    data: [u8; 8],
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct QuicConnectionClose {
    common: QuicFrameCommon,
    error_code: u64,
    frame_type: u64,
    reason: String,
}

#[allow(dead_code)]
#[derive(Clone, Default, Debug)]
struct QuicFrameCommon {
    level: Option<QuicLevel>,
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

                if remain < 5 * 8 {
                    warn!(
                        "Should provide more buffer for Ack frame, only got {} bytes",
                        remain
                    );
                    return Ok(false);
                }

                let frame_type: u8 = QuicFrameType::Ack.into();
                let start_pos = cursor.stream_position()?;
                encode_variable_length(cursor, frame_type as u64)?;
                encode_variable_length(cursor, ack_frame.largest_acknowledged)?;
                encode_variable_length(cursor, ack_frame.ack_delay)?;
                let consumed_size = cursor.stream_position()?.saturating_sub(start_pos);

                let remain_bytes = (remain as u64).saturating_sub(consumed_size);
                let range_count = remain_bytes.saturating_sub(2 * 8).div(2 * 8);
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

                // TODO: check it more accurate
                if remain < 10 + crypto_frame.crypto_data.len() as u16 {
                    return Ok(false);
                }

                let frame_type: u8 = QuicFrameType::Crypto.into();
                encode_variable_length(cursor, frame_type as u64)?;
                encode_variable_length(cursor, crypto_frame.offset)?;
                encode_variable_length(cursor, crypto_frame.crypto_data.len() as u64)?;
                cursor.write_all(&crypto_frame.crypto_data)?;

                trace!("Serialized {:?} frame", QuicFrameType::Crypto);
            }
            QuicFrame::Ping(_) => {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
                let frame_type: u8 = QuicFrameType::Ping.into();
                encode_variable_length(cursor, frame_type as u64)?;

                trace!("Serialized {:?} frame", QuicFrameType::Ping);
            }
            _ => unimplemented!(),
        }

        Ok(true)
    }

    pub(crate) fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            QuicFrame::Ack(_) | QuicFrame::Padding(_) | QuicFrame::ConnectionClose(_)
        )
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
        let send_ctx = match level {
            QuicLevel::Initial => &mut qconn.init_send,
            QuicLevel::Handshake => &mut qconn.hs_send,
            QuicLevel::Application => &mut qconn.app_send,
        };

        let mut ack_frames: VecDeque<QuicFrame> = VecDeque::new();
        if let Some(single_pns) = send_ctx.get_single_ack_pns() {
            single_pns.iter().for_each(|pn| {
                ack_frames.push_back(QuicFrame::Ack(QuicAck {
                    common: QuicFrameCommon {
                        level: Some(level),
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
                level: Some(level),
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

    pub(crate) fn handle_quic_frame(qconn: &mut QuicConnection, pkt: &QuicPacket) -> Result<bool> {
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

        let mut need_ack = false;
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
                QuicFrameType::Ack => Self::handle_ack_frame(&mut cursor, qconn, level)?,
                QuicFrameType::Ping => Self::handle_ping_frame(&mut cursor, qconn, level)?,
                QuicFrameType::Padding => Self::handle_padding_frame(&mut cursor, qconn, level)?,
                QuicFrameType::HandshakeDone => {
                    Self::handle_handshake_done_frame(&mut cursor, qconn, level)?
                }
                QuicFrameType::NewConnectionId => {
                    Self::handle_new_conncetion_id_frame(&mut cursor, qconn, level)?
                }
                QuicFrameType::NewToken => Self::handle_new_token_frame(&mut cursor, qconn, level)?,
                QuicFrameType::Stream => {
                    // TODO: support QUIC stream
                    let mut tmp = vec![0u8; pbuf.len() - cursor.position() as usize];
                    cursor.read_exact(&mut tmp)?;
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
        matches!(
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
                if send_ctx.get_recv_cbufs_length() + length > QUIC_CRYPTO_FRAME_MAX_BUFFER_SIZE {
                    // TODO: Need to close connection with `CRYPTO_BUFFER_EXCEEDED`
                    return Ok(());
                }
                send_ctx.insert_recv_cbufs(
                    &cursor.get_ref()
                        [crypto_start_pos as usize..crypto_start_pos as usize + length as usize],
                    offset,
                );
                cursor.seek_relative(length as i64)?;
                return Ok(());
            }
            Ordering::Greater => {
                trace!(
                    "Out-of-order CRYPTO frame has been received: expected offset={}, got={}",
                    send_ctx.crypto_recv_offset,
                    offset
                );

                // https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.3
                send_ctx.resend_all()?;
                qconn.set_next_send_event_time(0);

                return Ok(());
            }
            _ => (),
        }

        send_ctx.crypto_recv_offset += length;

        // Tls module must consume all the crypto buffer
        qconn.tls.handle_tls_handshake(
            &cursor.get_ref()
                [crypto_start_pos as usize..crypto_start_pos as usize + length as usize],
        )?;
        cursor.seek_relative(length as i64)?;

        if let Some(pre_buf) = send_ctx.consume_pre_recv_cbufs(offset + length) {
            trace!(
                "Continue to consume pre restored crypto bufs, offset {}, length {}, crypto_recv_offset {}",
                offset + length,
                pre_buf.len(),
                send_ctx.crypto_recv_offset,
            );
            qconn.tls.handle_tls_handshake(&pre_buf)?;
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
            if qconn.idle_timeout.is_none() {
                // Max_idle_timeout: Idle timeout is disabled when both endpoints
                // omit this transport parameter or specify a value of 0.
                let peer_idle_timeout = qconn.tls.get_peer_idle_timeout().unwrap_or(0);
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
                if let Some(mad) = qconn.tls.get_peer_max_ack_delay() {
                    qconn.rtt.max_ack_delay = Some(mad);
                }
            }

            if qconn.rtt.ack_delay_exponent.is_none() {
                if let Some(ade) = qconn.tls.get_peer_ack_delay_exponent() {
                    qconn.rtt.ack_delay_exponent = Some(ade);
                }
            }
        }

        qconn.consume_tls_send_queue()?;

        Ok(())
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

        qconn
            .new_conn_ids
            .push((scid, stateless_reset_token.to_vec()));

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

        trace!("Now we are creating {:?} ping frame", level,);

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

        // TODO: need to ack

        Ok(())
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
        send_ctx.handle_ack_frame(
            first_ack_range,
            largest_acked,
            &ack_ranges,
            &mut qconn.rtt,
            level,
            &qconn.current_ts,
            ack_delay,
        )?;

        qconn.reset_pto_backoff_factor();
        qconn.detect_lost()?;
        qconn.set_loss_or_pto_timer()?;

        if !ack_ranges.is_empty() {
            trace!(
                "Processing ack frame, we received ack ranges {:?}",
                ack_ranges
            );
        }

        Ok(())
    }
}
