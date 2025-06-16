use anyhow::{anyhow, Context, Result};
use std::cmp::Ordering;
use std::io::{Cursor, Seek};
use thiserror::Error;
use tracing::{error, info, span, trace, warn, Level};

use crate::buffer::QuicBuffer;
use crate::flow_control::QuicStreamFlowControl;
use crate::frame::{QuicFrame, QuicResetStream, QuicStreamFrame};

#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct QuicStreamHandle(u64);

impl QuicStreamHandle {
    pub(crate) fn new(stream_id: u64) -> Self {
        Self(stream_id)
    }

    pub(crate) fn is_bidirectional(&self) -> bool {
        // Second least significant bit is 0 for bidirectional streams
        self.0 & 0x2 == 0
    }

    pub(crate) fn is_server_initiated(&self) -> bool {
        // Least significant bit is 1 for server-initiated streams
        self.0 & 0x1 == 1
    }

    pub(crate) fn is_client_initiated(&self) -> bool {
        // Least significant bit is 0 for client-initiated streams
        self.0 & 0x1 == 0
    }

    pub(crate) fn is_unidirectional(&self) -> bool {
        // Second least significant bit is 1 for unidirectional streams
        self.0 & 0x2 == 2
    }

    pub(crate) fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for QuicStreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let direction = if self.is_bidirectional() {
            "bidirectional"
        } else {
            "unidirectional"
        };
        let creator = if self.is_client_initiated() {
            "client-initiated"
        } else {
            "server-initiated"
        };
        write!(f, "{} ({}, {})", self.0, direction, creator)
    }
}

#[derive(Error, Debug)]
pub enum QuicStreamError {
    #[error("Resource is not available")]
    WouldBlock,

    #[error("Receiver was shutdown by the peer")]
    ReceiverShutdown,

    #[error("Receiver was reset by the peer, application error code {0}")]
    ReceiverReset(u64),

    #[error("Sender was shut down")]
    SenderReset,

    #[error("Must not send data on the unidirectional and server-initiated stream")]
    SendWrongUniStream,

    #[error("Must not receive data on the unidirectional and client-initiated stream")]
    RecvWrongUniStream,

    #[error("Expected or set sending stream state is {0:?}, but current invalid state is {1:?}")]
    InvalidSendingStreamState(String, String),
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
enum QuicSendingStreamState {
    Ready,
    Send,
    DataSent,
    ResetSent,
    DataRecvd,
    ResetRecvd,
}

impl std::fmt::Display for QuicSendingStreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicSendingStreamState::Ready => write!(f, "Ready"),
            QuicSendingStreamState::Send => write!(f, "Send"),
            QuicSendingStreamState::DataSent => write!(f, "DataSent"),
            QuicSendingStreamState::ResetSent => write!(f, "ResetSent"),
            QuicSendingStreamState::DataRecvd => write!(f, "DataRecvd"),
            QuicSendingStreamState::ResetRecvd => write!(f, "ResetRecvd"),
        }
    }
}

// Sending Stream States
//        o
//        | Create Stream (Sending)
//        | Peer Creates Bidirectional Stream
//        v
//    +-------+
//    | Ready | Send RESET_STREAM
//    |       |-----------------------.
//    +-------+                       |
//        |                           |
//        | Send STREAM /             |
//        |      STREAM_DATA_BLOCKED  |
//        v                           |
//    +-------+                       |
//    | Send  | Send RESET_STREAM     |
//    |       |---------------------->|
//    +-------+                       |
//        |                           |
//        | Send STREAM + FIN         |
//        v                           v
//    +-------+                   +-------+
//    | Data  | Send RESET_STREAM | Reset |
//    | Sent  |------------------>| Sent  |
//    +-------+                   +-------+
//        |                           |
//        | Recv All ACKs             | Recv ACK
//        v                           v
//    +-------+                   +-------+
//    | Data  |                   | Reset |
//    | Recvd |                   | Recvd |
//    +-------+                   +-------+

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
enum QuicReceivingStreamState {
    Recv,
    SizeKnown,
    DataRecvd,
    ResetRecvd,
    DataRead,
    ResetRead,
}

// Receiving Stream States
//        o
//        | Recv STREAM / STREAM_DATA_BLOCKED / RESET_STREAM
//        | Create Bidirectional Stream (Sending)
//        | Recv MAX_STREAM_DATA / STOP_SENDING (Bidirectional)
//        | Create Higher-Numbered Stream
//        v
//    +-------+
//    | Recv  | Recv RESET_STREAM
//    |       |-----------------------.
//    +-------+                       |
//        |                           |
//        | Recv STREAM + FIN         |
//        v                           |
//    +-------+                       |
//    | Size  | Recv RESET_STREAM     |
//    | Known |---------------------->|
//    +-------+                       |
//        |                           |
//        | Recv All Data             |
//        v                           v
//    +-------+ Recv RESET_STREAM +-------+
//    | Data  |--- (optional) --->| Reset |
//    | Recvd |  Recv All Data    | Recvd |
//    +-------+<-- (optional) ----+-------+
//        |                           |
//        | App Read All Data         | App Read Reset
//        v                           v
//    +-------+                   +-------+
//    | Data  |                   | Reset |
//    | Read  |                   | Read  |
//    +-------+                   +-------+

pub(crate) struct QuicStream {
    stream_id: QuicStreamHandle,
    read_event_active: bool,
    write_event_active: bool,

    // Receiver
    recv_state: QuicReceivingStreamState,
    recv_bufs: QuicBuffer,
    recv_app_err_code: Option<u64>,
    stop_sending_sent: bool,

    // Sender
    send_state: QuicSendingStreamState,
    send_queue: Option<Vec<u8>>,
    received_stop_sending: bool,
    fin: bool, // Only indicate current sending status has a fin flag

    // Flow control
    flow_control: QuicStreamFlowControl,
}

impl std::fmt::Debug for QuicStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicStream")
            .field("stream_id", &self.stream_id)
            .field("read_event_active", &self.read_event_active)
            .field("write_event_active", &self.write_event_active)
            .field("recv_state", &self.recv_state)
            .field("recv_bufs_len", &self.recv_bufs)
            .field("send_state", &self.send_state)
            .field("send_queue_len", &self.send_queue.as_ref().map(|q| q.len()))
            .field("received_stop_sending", &self.received_stop_sending)
            .field("fin", &self.fin)
            .field("flow_control", &self.flow_control)
            .finish()
    }
}

impl QuicStream {
    pub(crate) fn new(stream_id: QuicStreamHandle, max_send_size: u64, max_recv_size: u64) -> Self {
        let span = span!(
            Level::TRACE,
            "creating new stream",
            stream_id = %stream_id,
            bidirectional = stream_id.is_bidirectional(),
            client_initiated = stream_id.is_client_initiated(),
        );
        let _enter = span.enter();

        let stream = Self {
            stream_id,
            read_event_active: false,
            recv_app_err_code: None,
            write_event_active: false,
            stop_sending_sent: false,
            send_state: QuicSendingStreamState::Ready,
            send_queue: None,
            received_stop_sending: false,
            recv_state: QuicReceivingStreamState::Recv,
            recv_bufs: QuicBuffer::default(),
            fin: false,
            flow_control: QuicStreamFlowControl::new(max_send_size, max_recv_size),
        };

        info!(
            "Created new stream {} (bidirectional: {}, client_initiated: {}, max_send: {}, max_recv: {})",
            stream_id,
            stream_id.is_bidirectional(),
            stream_id.is_client_initiated(),
            max_send_size,
            max_recv_size
        );
        trace!("Stream details: {:?}", stream);
        stream
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-2.4-2
    pub(crate) fn send(&mut self, snd_buf: &[u8]) -> Result<usize, QuicStreamError> {
        let span = span!(
            Level::TRACE,
            "sending data on stream",
            stream_id = %self.stream_id,
            data_len = snd_buf.len(),
            current_state = ?self.send_state
        );
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_server_initiated() {
            return Err(QuicStreamError::SendWrongUniStream);
        }

        if matches!(self.send_state, QuicSendingStreamState::DataSent)
            // Return Invalid state exception, if app layer called reset api before
            || (matches!(self.send_state, QuicSendingStreamState::ResetSent)
                && !self.received_stop_sending)
            || matches!(self.send_state, QuicSendingStreamState::DataRecvd)
            || matches!(self.send_state, QuicSendingStreamState::ResetRecvd)
        {
            return Err(QuicStreamError::InvalidSendingStreamState(
                QuicSendingStreamState::DataSent.to_string(),
                self.send_state.to_string(),
            ));
        }

        if matches!(self.send_state, QuicSendingStreamState::ResetSent) {
            return Err(QuicStreamError::SenderReset);
        }

        // Check stream-level flow control
        let available_bytes = match self.flow_control.get_sent_available_bytes() {
            Err(e) => panic!("Due to QUIC stream {:?} {e}", self),
            Ok(0) => {
                return Err(QuicStreamError::WouldBlock);
            }
            Ok(num) => num,
        };

        let sent_bytes = available_bytes.min(snd_buf.len() as u64);
        if let Some(ref mut send_queue) = self.send_queue {
            send_queue.extend(&snd_buf[..sent_bytes as usize]);
        } else {
            self.send_queue = Some(snd_buf[..sent_bytes as usize].into());
        }

        self.set_send_state(QuicSendingStreamState::Send);
        self.flow_control.increment_sent_bytes(sent_bytes);

        info!(
            "Stream {} sent {} bytes (requested: {}, available: {}, total: {}, max: {})",
            self.stream_id,
            sent_bytes,
            snd_buf.len(),
            available_bytes,
            self.flow_control.get_sent_bytes(),
            self.flow_control.get_max_send_size()
        );

        Ok(sent_bytes as usize)
    }

    pub(crate) fn finish(&mut self) -> Result<(), QuicStreamError> {
        let span = span!(Level::TRACE, "finishing stream", stream_id = %self.stream_id);
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_server_initiated() {
            return Err(QuicStreamError::SendWrongUniStream);
        }

        if !matches!(self.send_state, QuicSendingStreamState::Ready)
            && !matches!(self.send_state, QuicSendingStreamState::Send)
        {
            error!("Invalid stream state for finish: {:?}", self.send_state);
            return Err(QuicStreamError::InvalidSendingStreamState(
                QuicSendingStreamState::Ready.to_string(),
                self.send_state.to_string(),
            ));
        }

        self.set_send_state(QuicSendingStreamState::DataSent);
        self.write_event_active = false;
        self.fin = true;

        trace!(
            "Stream {} finished (sent {} bytes)",
            self.stream_id,
            self.flow_control.get_sent_offset()
        );
        Ok(())
    }

    pub(crate) fn stop_sending(
        &mut self,
        application_error_code: u64,
    ) -> Result<QuicFrame, QuicStreamError> {
        let span = span!(
            Level::TRACE,
            "stopping stream send",
            stream_id = %self.stream_id,
            error_code = application_error_code
        );
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_client_initiated() {
            return Err(QuicStreamError::RecvWrongUniStream);
        }

        trace!(
            "Stream {} stopping send with error code {}",
            self.stream_id,
            application_error_code
        );

        self.read_event_active = false;
        self.stop_sending_sent = true;

        Ok(QuicFrame::create_stop_sending_frame(
            self.stream_id.as_u64(),
            application_error_code,
        ))
    }

    pub(crate) fn reset(
        &mut self,
        application_error_code: u64,
    ) -> Result<QuicFrame, QuicStreamError> {
        let span = span!(
            Level::TRACE,
            "resetting stream",
            stream_id = %self.stream_id,
            error_code = application_error_code
        );
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_server_initiated() {
            return Err(QuicStreamError::SendWrongUniStream);
        }

        if !matches!(self.send_state, QuicSendingStreamState::Ready)
            && !matches!(self.send_state, QuicSendingStreamState::Send)
            && !matches!(self.send_state, QuicSendingStreamState::DataSent)
        {
            error!("Invalid stream state for reset: {:?}", self.send_state);
            return Err(QuicStreamError::InvalidSendingStreamState(
                QuicSendingStreamState::DataSent.to_string(),
                self.send_state.to_string(),
            ));
        }

        self.write_event_active = false;
        self.set_send_state(QuicSendingStreamState::ResetSent);

        trace!(
            "Stream {} reset with error code {} (sent {} bytes)",
            self.stream_id,
            application_error_code,
            self.flow_control.get_sent_offset()
        );
        Ok(QuicFrame::create_reset_stream_frame(
            self.stream_id.as_u64(),
            application_error_code,
            self.flow_control.get_sent_offset(),
        ))
    }

    pub(crate) fn get_new_max_recv_size(&self) -> u64 {
        self.flow_control.get_new_max_recv_size()
    }

    pub(crate) fn get_max_send_size(&self) -> u64 {
        self.flow_control.get_max_send_size()
    }

    pub(crate) fn check_if_update_max_recv_data(&mut self, do_it_anyway: bool) -> bool {
        self.flow_control
            .check_if_update_max_recv_size(do_it_anyway)
    }

    pub(crate) fn send_queue_is_empty(&self) -> bool {
        if let Some(ref send_queue) = self.send_queue {
            send_queue.is_empty()
        } else {
            true
        }
    }

    pub(crate) fn consume_send_queue(
        &mut self,
        max_buf_size: u64,
    ) -> Option<(Option<Vec<u8>>, u64, u64, bool)> {
        let span = span!(
            Level::TRACE,
            "consuming stream send queue",
            stream_id = %self.stream_id,
            queue_empty = self.send_queue.is_none(),
            fin = self.fin
        );
        let _enter = span.enter();

        match self.send_queue.take() {
            Some(mut send_queue) => {
                let offset = self.flow_control.get_sent_offset();
                let fin = self.fin;

                let send_len = if max_buf_size < send_queue.len() as u64 {
                    let new_queue = send_queue.split_off(max_buf_size as usize);
                    trace!(
                        "Split send queue: original={}, split={}, remaining={}",
                        send_queue.len() + new_queue.len(),
                        max_buf_size,
                        new_queue.len()
                    );
                    self.send_queue = Some(new_queue);
                    max_buf_size
                } else {
                    send_queue.len() as u64
                };

                // Reset or update the stream
                self.fin = false;
                self.flow_control.increment_sent_offset(send_len);

                trace!(
                    "Consumed send queue: stream={}, offset={}, length={}, fin={}",
                    self.stream_id,
                    offset,
                    send_len,
                    fin,
                );

                Some((Some(send_queue), offset, self.stream_id.as_u64(), fin))
            }
            None => {
                if self.fin {
                    self.fin = false;
                    trace!(
                        "Consumed fin flag: stream={}, offset={}",
                        self.stream_id,
                        self.flow_control.get_sent_offset()
                    );
                    Some((
                        None,
                        self.flow_control.get_sent_offset(),
                        self.stream_id.as_u64(),
                        true,
                    ))
                } else {
                    trace!("No data to consume from send queue");
                    None
                }
            }
        }
    }

    pub(crate) fn ack_reset_stream(
        &mut self,
        _frame: &QuicResetStream,
    ) -> Result<(), QuicStreamError> {
        self.set_send_state(QuicSendingStreamState::ResetRecvd);
        trace!(
            "Stream {} reset stream frame has been acked",
            self.stream_id
        );

        Ok(())
    }

    pub(crate) fn ack_stream(&mut self, frame: &QuicStreamFrame) -> Result<()> {
        // Duplicated ack won't happen
        self.flow_control.increment_sent_acked(frame.length);

        if frame.is_fin {
            // The Fin is acked here
            trace!("Stream {} fin flag has been acked", self.stream_id);
        }

        if matches!(self.send_state, QuicSendingStreamState::DataSent)
            && self.flow_control.get_sent_in_flight()? == 0
        {
            self.set_send_state(QuicSendingStreamState::DataRecvd);
            trace!("Stream {} sender job has been done", self.stream_id);

            return Ok(());
        }

        self.flow_control.set_writable(true);
        trace!("Trigger the write event");

        Ok(())
    }

    pub(crate) fn recv(&mut self, rcv_size: usize) -> Result<Vec<u8>, QuicStreamError> {
        let span = span!(
            Level::TRACE,
            "receiving from stream",
            stream_id = %self.stream_id,
            size = rcv_size
        );
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_client_initiated() {
            error!(
                "Attempted to receive on client-initiated unidirectional stream {}",
                self.stream_id
            );
            return Err(QuicStreamError::RecvWrongUniStream);
        }

        trace!(
            "Attempting to receive {} bytes from stream {}",
            rcv_size,
            self.stream_id
        );

        // Like epoll ET mode
        self.flow_control.set_readable(false);

        if matches!(self.recv_state, QuicReceivingStreamState::ResetRecvd)
            || matches!(self.recv_state, QuicReceivingStreamState::ResetRead)
        {
            self.set_recv_state(QuicReceivingStreamState::ResetRead);
            trace!("Stream {} was reset by peer", self.stream_id);
            return Err(QuicStreamError::ReceiverReset(
                self.recv_app_err_code.unwrap(),
            ));
        }

        match self
            .recv_bufs
            .consume(self.flow_control.get_recv_pos(), rcv_size)
        {
            Some(v) => {
                if v.len() > rcv_size {
                    panic!(
                        "Received more data than requested: {} > {}",
                        v.len(),
                        rcv_size
                    );
                }
                trace!(
                    "Successfully received {} bytes from stream {}",
                    v.len(),
                    self.stream_id
                );
                self.flow_control.increment_recv_pos(v.len() as u64);
                Ok(v)
            }
            None => {
                if matches!(self.recv_state, QuicReceivingStreamState::DataRecvd) {
                    self.set_recv_state(QuicReceivingStreamState::DataRead);
                    trace!("Stream {} has no more data to receive", self.stream_id);
                    Err(QuicStreamError::ReceiverShutdown)
                } else {
                    trace!("Stream {} has no data available", self.stream_id);
                    Err(QuicStreamError::WouldBlock)
                }
            }
        }
    }

    pub(crate) fn set_read_active(&mut self, flag: bool) {
        let span = span!(
            Level::TRACE,
            "setting stream read active",
            stream_id = %self.stream_id,
            active = flag
        );
        let _enter = span.enter();

        self.read_event_active = flag;
        trace!("Set read active={} for stream {}", flag, self.stream_id);
    }

    pub(crate) fn set_write_active(&mut self, flag: bool) {
        let span = span!(
            Level::TRACE,
            "setting stream write active",
            stream_id = %self.stream_id,
            active = flag
        );
        let _enter = span.enter();

        self.write_event_active = flag;
        trace!("Set write active={} for stream {}", flag, self.stream_id);
    }

    pub(crate) fn check_new_stream_id(stream_id: QuicStreamHandle) -> Result<()> {
        let span = span!(Level::TRACE, "checking new stream id", stream_id = %stream_id);
        let _enter = span.enter();

        if stream_id.is_client_initiated() {
            error!(
                "Invalid stream ID {}: client-initiated stream must exist",
                stream_id
            );
            return Err(anyhow!("Client-initiated Stream must exist"));
        }

        if stream_id.is_unidirectional() && stream_id.is_client_initiated() {
            error!(
                "Invalid stream ID {}: unidirectional stream must not be received",
                stream_id
            );
            return Err(anyhow!("Unidirectional Stream must not received"));
        }

        trace!("Stream ID {} is valid", stream_id);
        Ok(())
    }

    pub(crate) fn update_max_stream_data(&mut self, max_data: u64) -> Result<()> {
        trace!(
            "Stream {} received max stream data frame with max_data={}",
            self.stream_id,
            max_data
        );

        if self.stream_id.is_unidirectional() && self.stream_id.is_server_initiated() {
            error!(
                "Invalid stream ID {}: unidirectional stream must not be received",
                self.stream_id
            );
            return Err(anyhow!("Unidirectional Stream must not received"));
        }

        self.flow_control.update_max_send_size(max_data)?;
        trace!(
            "Updated stream {} max send size to {}",
            self.stream_id,
            max_data
        );

        self.update_max_recv_data(max_data)
    }

    fn update_max_recv_data(&mut self, max_data: u64) -> Result<()> {
        trace!(
            "Stream {} received max receive data update with max_data={}",
            self.stream_id,
            max_data
        );

        self.flow_control.update_max_recv_size(max_data)?;
        trace!(
            "Updated stream {} max receive size to {}",
            self.stream_id,
            max_data
        );

        Ok(())
    }

    pub(crate) fn handle_reset_stream_frame(
        &mut self,
        application_error_code: u64,
        final_size: u64,
    ) -> Result<()> {
        let span = span!(
            Level::TRACE,
            "handling reset stream frame",
            stream_id = %self.stream_id,
            error_code = application_error_code,
            final_size
        );
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_client_initiated() {
            return Err(anyhow!(
                "Never expect receive reset stream frame on this stream {}",
                self.stream_id
            ));
        }

        if !matches!(self.recv_state, QuicReceivingStreamState::Recv)
            && !matches!(self.recv_state, QuicReceivingStreamState::SizeKnown)
            && !matches!(self.recv_state, QuicReceivingStreamState::DataRecvd)
        {
            warn!(
                "Stream {} in state {:?} doesn't need to reply with reset stream frame, \
                error code {}, final_size {}",
                self.stream_id, self.recv_state, application_error_code, final_size
            );
            return Ok(());
        }

        self.flow_control.set_recv_final_size(final_size)?;

        self.set_recv_state(QuicReceivingStreamState::ResetRecvd);
        if !self.stop_sending_sent {
            // If receiver was shut down by the application layer,
            // we should not notity the application layer
            self.flow_control.set_readable(true);
        }
        self.recv_app_err_code = Some(application_error_code);
        trace!(
            "Stream {} receiving was reset by peer with error code {}",
            self.stream_id,
            application_error_code
        );
        Ok(())
    }

    pub(crate) fn handle_stop_sending_frame(
        &mut self,
        application_error_code: u64,
    ) -> Result<Option<QuicFrame>> {
        let span = span!(
            Level::TRACE,
            "handling stop sending frame",
            stream_id = %self.stream_id,
            error_code = application_error_code
        );
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_server_initiated() {
            return Err(anyhow!(
                "Never expect receive stop sending frame on this stream {}",
                self.stream_id
            ));
        }

        if !matches!(self.send_state, QuicSendingStreamState::Ready)
            && !matches!(self.send_state, QuicSendingStreamState::Send)
            && !matches!(self.send_state, QuicSendingStreamState::DataSent)
        {
            warn!(
                "Stream {} in state {:?} doesn't need to reply with stop sending frame, error code {}",
                self.stream_id, self.send_state, application_error_code
            );
            return Ok(None);
        }

        self.received_stop_sending = true;
        self.set_send_state(QuicSendingStreamState::ResetSent);

        trace!(
            "Stream {} sending was reset by peer with error code {}, final size {}",
            self.stream_id,
            application_error_code,
            self.flow_control.get_sent_offset(),
        );
        Ok(Some(QuicFrame::create_reset_stream_frame(
            self.stream_id.as_u64(),
            application_error_code,
            self.flow_control.get_sent_offset(),
        )))
    }

    pub(crate) fn handle_stream_frame(
        &mut self,
        offset: u64,
        length: u64,
        fin_bit: bool,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<()> {
        let span = span!(
            Level::TRACE,
            "handling stream frame",
            stream_id = %self.stream_id,
            offset,
            length,
            fin = fin_bit
        );
        let _enter = span.enter();

        if self.stream_id.is_unidirectional() && self.stream_id.is_client_initiated() {
            error!(
                "Received frame on client-initiated unidirectional stream {}",
                self.stream_id
            );
            return Err(anyhow!(
                "client-initiated and Unidirectional Stream must not receive frame"
            ));
        }

        if matches!(self.recv_state, QuicReceivingStreamState::ResetRecvd)
            || matches!(self.recv_state, QuicReceivingStreamState::ResetRead)
        {
            trace!(
                "Just skip the {} stream frame handle, since recv state is {:?}",
                self.stream_id,
                self.recv_state
            );
            return Ok(());
        }

        let last = offset + length;
        // Check receive flow control before processing the frame
        self.flow_control.check_recv_flow_control(last)?;

        let mut check_offset = false;
        match self.flow_control.get_recv_offset().cmp(&offset) {
            Ordering::Less => {
                trace!(
                    "Out-of-order Stream frame: expected offset={}, got={}",
                    self.flow_control.get_recv_offset(),
                    offset
                );
            }
            Ordering::Greater => {
                trace!(
                    "Out-of-order Stream frame: expected offset={}, got={}, \
                    length {}, just drop the frame",
                    self.flow_control.get_recv_offset(),
                    offset,
                    length
                );
                cursor.seek_relative(length as i64)?;
                return Ok(());
            }
            Ordering::Equal => {
                self.flow_control.increment_recv_offset(length);
                check_offset = true;
                if length > 0 || fin_bit {
                    self.flow_control.set_readable(true);
                    trace!("Triggered read event for stream {}", self.stream_id);
                }
            }
        }

        if fin_bit {
            trace!("Stream {} received STREAM + FIN", self.stream_id);
            self.set_recv_state(QuicReceivingStreamState::SizeKnown);
            self.flow_control
                .set_recv_final_size(last)
                .with_context(|| format!("Stream {}", self.stream_id))?;
        }

        let pos = cursor.position();
        self.recv_bufs.insert(
            &cursor.get_ref()[pos as usize..(pos + length) as usize],
            offset,
        );
        cursor.seek_relative(length as i64)?;
        self.flow_control.set_recv_largest(last);

        if check_offset {
            self.flow_control.increment_recv_offset(
                self.recv_bufs
                    .get_recv_offset_increament_size(self.flow_control.get_recv_offset()),
            );
        }

        if self
            .flow_control
            .get_recv_final_size()
            .map(|final_size| final_size == self.flow_control.get_recv_offset())
            .unwrap_or(false)
        {
            self.set_recv_state(QuicReceivingStreamState::DataRecvd);
        }

        trace!(
            "Successfully processed stream frame for stream {}",
            self.stream_id
        );
        Ok(())
    }

    pub(crate) fn is_readable(&self) -> bool {
        let readable = self.read_event_active && self.flow_control.is_readable();
        trace!(
            "Stream {} readable status: {} (read_event_active={}, readable={})",
            self.stream_id,
            readable,
            self.read_event_active,
            self.flow_control.is_readable()
        );
        readable
    }

    pub(crate) fn is_writable(&self) -> bool {
        let writable = self.write_event_active && self.flow_control.is_writable();
        trace!(
            "Stream {} writable status: {} (write_event_active={}, writable={})",
            self.stream_id,
            writable,
            self.write_event_active,
            self.flow_control.is_writable()
        );
        writable
    }

    fn is_send_ready_for_clean(&self) -> bool {
        matches!(self.send_state, QuicSendingStreamState::DataRecvd)
            || matches!(self.send_state, QuicSendingStreamState::ResetRecvd)
    }

    fn is_recv_ready_for_clean(&self) -> bool {
        matches!(self.recv_state, QuicReceivingStreamState::DataRead)
            || matches!(self.recv_state, QuicReceivingStreamState::ResetRead)
    }

    pub(crate) fn should_clean_stream(&self) -> bool {
        if self.stream_id.is_bidirectional() {
            self.is_send_ready_for_clean() && self.is_recv_ready_for_clean()
        } else if self.stream_id.is_server_initiated() {
            self.is_recv_ready_for_clean()
        } else {
            self.is_send_ready_for_clean()
        }
    }

    fn set_recv_state(&mut self, state: QuicReceivingStreamState) {
        if self.recv_state == state {
            return;
        }

        trace!(
            "Stream {} receiving state changed from {:?} to {:?}",
            self.stream_id,
            self.recv_state,
            state
        );
        self.recv_state = state;
    }

    fn set_send_state(&mut self, state: QuicSendingStreamState) {
        if self.send_state == state {
            return;
        }

        trace!(
            "Stream {} sending state changed from {:?} to {:?}",
            self.stream_id,
            self.send_state,
            state
        );
        self.send_state = state;
    }

    // TODO: https://www.rfc-editor.org/rfc/rfc9000.html#section-2.3
}
