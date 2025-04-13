use anyhow::{anyhow, Result};
use tracing::{info, trace, warn};

#[derive(Debug, Default)]
pub(crate) struct QuicConnectionFlowControl {
    // recv_offset .. recv_max_data
    // e.g. 100 .. 800
    // application layer call `stream_recv`, and if there are 200 bytes left in the QuicBuffer
    // 300 .. 800
    // receive stream frame contains [400, 500]
    // still 300 .. 800, QuicBuffer will handle the hole and store the bytes
    connection_recv_max_data: u64,
    connection_recv_window: u64,
    connection_recv_offset: u64,

    // sent_acked .. sent_offset .. send_max_data
    // e.g.   100 .. 200 .. 500
    // application layer call `stream_send` to send 80 bytes
    // 100 .. 280 .. 500
    // acked the stream frame contains [100, 200]
    // 200 .. 280 .. 500
    // received stream data frame (800)
    // 200 .. 280 .. 800
    connection_send_max_data: u64,
    connection_sent_offset: u64,
    connection_sent_acked: u64,

    // Stream count limits
    local_max_bidi_streams: u64,
    local_max_uni_streams: u64,
    remote_max_bidi_streams: u64,
    remote_max_uni_streams: u64,

    // Current stream counts
    local_bidi_stream_count: u64,
    remote_bidi_stream_count: u64,
    local_uni_stream_count: u64,
    remote_uni_stream_count: u64,
}

impl QuicConnectionFlowControl {
    pub(crate) fn new() -> Self {
        info!("Creating new QuicConnectionFlowControl instance");
        Self::default()
    }

    pub(crate) fn check_if_update_max_recv_data(&mut self, do_it_anyway: bool) -> bool {
        if do_it_anyway {
            return self.get_new_max_recv_size() > self.connection_recv_max_data;
        }

        match self.get_recv_available_bytes() {
            Ok(bytes) => {
                if bytes <= self.connection_recv_window / 2 {
                    info!(
                        "Updating connection recv max data from {} to {}",
                        self.connection_recv_max_data,
                        self.connection_recv_offset + self.connection_recv_window
                    );
                    self.connection_recv_max_data =
                        self.connection_recv_offset + self.connection_recv_window;
                    true
                } else {
                    false
                }
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    pub(crate) fn get_max_send_size(&self) -> u64 {
        self.connection_send_max_data
    }

    pub(crate) fn get_new_max_recv_size(&self) -> u64 {
        self.connection_recv_offset + self.connection_recv_window
    }

    pub(crate) fn get_recv_available_bytes(&self) -> Result<u64> {
        self.connection_recv_max_data
            .checked_sub(self.connection_recv_offset)
            .ok_or_else(|| {
                anyhow!(
                    "Invalid connection recv max size {} and recv offset {}",
                    self.connection_recv_max_data,
                    self.connection_recv_offset
                )
            })
    }

    pub(crate) fn increment_recv_offset(&mut self, bytes: u64) {
        self.connection_recv_offset += bytes;
        trace!(
            "Incremented connection recv bytes by {}, recv offset {}",
            bytes,
            self.connection_recv_offset
        );
    }

    pub(crate) fn get_sent_available_bytes(&self) -> Result<u64> {
        self.connection_send_max_data
            .checked_sub(self.connection_sent_offset)
            .ok_or_else(|| {
                anyhow!(
                    "Invalid connection send max size {} and send offset {}",
                    self.connection_send_max_data,
                    self.connection_sent_offset
                )
            })
    }

    pub(crate) fn increment_sent_acked(&mut self, bytes: u64) {
        self.connection_sent_acked += bytes;
        trace!(
            "Incremented connection sent acked by {}, sent acked {}",
            bytes,
            self.connection_sent_acked
        );
    }

    pub(crate) fn increment_sent_offset(&mut self, bytes: u64) {
        self.connection_sent_offset += bytes;
        trace!(
            "Incremented connection send offset by {}, send offset {}",
            bytes,
            self.connection_sent_offset
        );
    }

    pub(crate) fn handle_max_data_frame(&mut self, max_data: u64) -> Result<()> {
        if max_data < self.connection_send_max_data {
            return Ok(());
        }
        info!(
            "Received MAX_DATA frame: updating connection_send_max_data from {} to {}",
            self.connection_send_max_data, max_data
        );
        self.connection_send_max_data = max_data;

        Ok(())
    }

    pub(crate) fn get_max_streams_bidi_local(&self) -> Option<u64> {
        Some(self.local_max_bidi_streams)
    }

    pub(crate) fn get_max_streams_uni_local(&self) -> Option<u64> {
        Some(self.local_max_uni_streams)
    }

    pub(crate) fn get_max_streams_bidi_remote(&self) -> Option<u64> {
        Some(self.remote_max_bidi_streams)
    }

    pub(crate) fn get_max_streams_uni_remote(&self) -> Option<u64> {
        Some(self.remote_max_uni_streams)
    }

    pub(crate) fn handle_max_streams_frame(
        &mut self,
        is_bidirectional: bool,
        max_streams: u64,
    ) -> Result<()> {
        // Max streams is a count of the cumulative number of streams
        if is_bidirectional {
            if max_streams > self.remote_max_bidi_streams {
                info!(
                    "Received MAX_STREAMS_BIDI frame: updating remote_max_bidi_streams from {} to {}",
                    self.remote_max_bidi_streams, max_streams
                );
                self.remote_max_bidi_streams = max_streams;
            } else {
                warn!(
                    "Received MAX_STREAMS_BIDI frame with max_streams={} \
                    is less than peer's current limit={}",
                    max_streams, self.remote_max_bidi_streams
                );
            }
        } else if max_streams > self.remote_max_uni_streams {
            info!(
                "Received MAX_STREAMS_UNI frame: updating remote_max_uni_streams from {} to {}",
                self.remote_max_uni_streams, max_streams
            );
            self.remote_max_uni_streams = max_streams;
        } else {
            warn!(
                "Received MAX_STREAMS_UNI frame with max_streams={} \
                is less than peer's current limit={}",
                max_streams, self.remote_max_uni_streams
            );
        }
        Ok(())
    }

    // Stream count tracking methods
    pub(crate) fn increment_bi_stream_local(&mut self) {
        self.local_bidi_stream_count += 1;
        info!(
            "Incremented local bidirectional stream count to {}",
            self.local_bidi_stream_count
        );
    }

    pub(crate) fn increment_bi_stream_remote(&mut self) {
        self.remote_bidi_stream_count += 1;
        info!(
            "Incremented remote bidirectional stream count to {}",
            self.remote_bidi_stream_count
        );
    }

    pub(crate) fn increment_uni_stream_local(&mut self) {
        self.local_uni_stream_count += 1;
        info!(
            "Incremented local unidirectional stream count to {}",
            self.local_uni_stream_count
        );
    }

    pub(crate) fn increment_uni_stream_remote(&mut self) {
        self.remote_uni_stream_count += 1;
        info!(
            "Incremented remote unidirectional stream count to {}",
            self.remote_uni_stream_count
        );
    }

    pub(crate) fn get_bi_stream_local_cnt(&self) -> u64 {
        self.local_bidi_stream_count
    }

    pub(crate) fn get_bi_stream_remote_cnt(&self) -> u64 {
        self.remote_bidi_stream_count
    }

    pub(crate) fn get_uni_stream_local_cnt(&self) -> u64 {
        self.local_uni_stream_count
    }

    pub(crate) fn get_uni_stream_remote_cnt(&self) -> u64 {
        self.remote_uni_stream_count
    }

    // Initialization methods
    pub(crate) fn set_initial_limits(
        &mut self,
        recv_max_data: u64,
        send_max_data: u64,
        max_streams_bidi_local: u64,
        max_streams_uni_local: u64,
        max_streams_bidi_remote: u64,
        max_streams_uni_remote: u64,
    ) {
        info!(
            "Setting initial flow control limits: recv_max_data={}, send_max_data={}, \
            max_streams_bidi_local={}, max_streams_uni_local={}, \
            max_streams_bidi_remote={}, max_streams_uni_remote={}",
            recv_max_data,
            send_max_data,
            max_streams_bidi_local,
            max_streams_uni_local,
            max_streams_bidi_remote,
            max_streams_uni_remote
        );
        self.connection_recv_max_data = recv_max_data;
        self.connection_recv_window = recv_max_data;
        self.connection_send_max_data = send_max_data;
        self.local_max_bidi_streams = max_streams_bidi_local;
        self.local_max_uni_streams = max_streams_uni_local;
        self.remote_max_bidi_streams = max_streams_bidi_remote;
        self.remote_max_uni_streams = max_streams_uni_remote;
    }
}

#[derive(Debug, Default)]
pub(crate) struct QuicStreamFlowControl {
    // Stream level flow control

    // sent_acked .. sent_bytes .. send_max_data
    // e.g.   100 .. 200 .. 500
    // application layer call `stream_send` to send 80 bytes
    // 100 .. 280 .. 500
    // acked the stream frame contains [100, 200]
    // 200 .. 280 .. 500
    // received stream data frame (800)
    // 200 .. 280 .. 800
    max_send_size: u64,
    sent_acked: u64,
    // There is a gap between `stream_send` and `consume_send_queue`
    // Using `sent_bytes` and `sent_offset` to distinguish this gap
    sent_bytes: u64,
    sent_offset: u64,

    // recv_pos .. recv_offset .. recv_max_data
    // e.g. 100 .. 400 .. 800
    // application layer call `stream_recv`
    // 300 .. 400 .. 800
    // receive stream frame contains [400, 500]
    // 300 .. 500 .. 800
    max_recv_size: u64,
    recv_offset: u64,
    recv_largest: u64,
    recv_pos: u64,
    recv_window: u64,
    recv_final_size: Option<u64>,
    writable: bool,
    readable: bool,
}

impl QuicStreamFlowControl {
    pub(crate) fn new(max_send_size: u64, max_recv_size: u64) -> Self {
        info!(
            "Creating new stream flow control with max_send_size={}, max_recv_size={}",
            max_send_size, max_recv_size
        );
        Self {
            max_send_size,
            max_recv_size,
            sent_acked: 0,
            sent_bytes: 0,
            sent_offset: 0,
            recv_offset: 0,
            recv_largest: 0,
            recv_pos: 0,
            recv_window: max_recv_size,
            recv_final_size: None,
            writable: max_send_size > 0,
            readable: false,
        }
    }

    // Send flow control methods
    pub(crate) fn get_max_send_size(&self) -> u64 {
        self.max_send_size
    }

    pub(crate) fn get_sent_in_flight(&self) -> Result<u64> {
        self.sent_bytes.checked_sub(self.sent_acked).ok_or_else(|| {
            anyhow!(
                "Invalid send acked {} and send offset {}",
                self.sent_acked,
                self.sent_bytes
            )
        })
    }

    pub(crate) fn get_sent_available_bytes(&self) -> Result<u64> {
        self.max_send_size
            .checked_sub(self.sent_bytes)
            .ok_or_else(|| {
                anyhow!(
                    "Invalid send max size {} and send bytes {}",
                    self.max_send_size,
                    self.sent_bytes
                )
            })
    }

    pub(crate) fn get_sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    pub(crate) fn get_sent_offset(&self) -> u64 {
        self.sent_offset
    }

    pub(crate) fn increment_sent_acked(&mut self, bytes: u64) {
        self.sent_acked += bytes;
        trace!(
            "Incremented send acked by {}, send acked {}",
            bytes,
            self.sent_acked
        );
    }

    pub(crate) fn increment_sent_bytes(&mut self, bytes: u64) {
        self.sent_bytes += bytes;
        trace!(
            "Incremented send bytes by {}, send bytes {}",
            bytes,
            self.sent_bytes
        );
    }

    pub(crate) fn increment_sent_offset(&mut self, bytes: u64) {
        self.sent_offset += bytes;
        trace!(
            "Incremented send offset by {}, send offset {}",
            bytes,
            self.sent_offset
        );
    }

    pub(crate) fn update_max_send_size(&mut self, max_data: u64) -> Result<()> {
        info!(
            "Updating max send size from {} to {}",
            self.max_send_size, max_data
        );

        if max_data <= self.max_send_size {
            warn!(
                "New max send size {} is less than or equal to current max send size {}",
                max_data, self.max_send_size
            );
            return Ok(());
        }

        self.max_send_size = max_data;

        // If we were blocked by flow control, we might be able to send more data now
        if self.get_sent_bytes() < self.max_send_size {
            info!(
                "Recevied max stream data, stream is writable now, sent bytes {}",
                self.get_sent_bytes()
            );
            self.writable = true;
        }

        Ok(())
    }

    pub(crate) fn get_new_max_recv_size(&self) -> u64 {
        self.recv_offset + self.recv_window
    }

    pub(crate) fn get_recv_offset(&self) -> u64 {
        self.recv_offset
    }

    pub(crate) fn check_recv_flow_control(&self, last: u64) -> Result<()> {
        if last > self.max_recv_size {
            return Err(anyhow!("Receive flow control limit exceeded"));
        }
        Ok(())
    }

    pub(crate) fn check_if_update_max_recv_size(&mut self, do_it_anyway: bool) -> bool {
        if do_it_anyway {
            return self.get_new_max_recv_size() > self.max_recv_size;
        }

        match self.get_recv_available_bytes() {
            Ok(bytes) => {
                if bytes <= self.max_recv_size / 2 {
                    info!(
                        "Updating connection recv max data from {} to {}",
                        self.max_recv_size,
                        self.recv_offset + self.max_recv_size
                    );
                    self.max_recv_size += self.recv_offset;
                    true
                } else {
                    false
                }
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    pub(crate) fn get_recv_available_bytes(&self) -> Result<u64> {
        self.max_recv_size
            .checked_sub(self.recv_offset)
            .ok_or_else(|| {
                anyhow!(
                    "Invalid stream recv max size {} and recv offset {}",
                    self.max_recv_size,
                    self.recv_offset
                )
            })
    }

    pub(crate) fn update_max_recv_size(&mut self, max_data: u64) -> Result<()> {
        info!(
            "Updating max receive size from {} to {}",
            self.max_recv_size, max_data
        );

        if max_data <= self.max_recv_size {
            warn!(
                "New max receive size {} is less than or equal to current max receive size {}",
                max_data, self.max_recv_size
            );
            return Ok(());
        }

        self.max_recv_size = max_data;
        Ok(())
    }

    pub(crate) fn get_recv_pos(&self) -> u64 {
        self.recv_pos
    }

    pub(crate) fn increment_recv_pos(&mut self, bytes: u64) {
        self.recv_pos += bytes;
        trace!(
            "Incremented receive pos by {}, total received={}",
            bytes,
            self.recv_pos
        );
    }

    pub(crate) fn set_recv_largest(&mut self, pos: u64) {
        if pos > self.recv_largest {
            self.recv_largest = pos;
        }
    }

    pub(crate) fn increment_recv_offset(&mut self, bytes: u64) {
        self.recv_offset += bytes;
        trace!(
            "Incremented receive offset by {}, total received={}",
            bytes,
            self.recv_offset
        );
    }

    pub(crate) fn set_recv_final_size(&mut self, size: u64) -> Result<()> {
        if size < self.recv_largest {
            return Err(anyhow!(
                "Invalid new final_size {}, larger then recv_largest {}",
                size,
                self.recv_largest
            ));
        }

        if let Some(final_size) = self.recv_final_size {
            if final_size != size {
                return Err(anyhow!(
                    "Invalid new final_size {}, old final_size {}",
                    size,
                    final_size
                ));
            }
        } else {
            self.recv_final_size = Some(size);
            info!("Set receive final size to {}", size);
        }
        Ok(())
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.writable
    }

    pub(crate) fn is_readable(&self) -> bool {
        self.readable
    }

    pub(crate) fn set_readable(&mut self, readable: bool) {
        self.readable = readable;
    }

    pub(crate) fn set_writable(&mut self, writable: bool) {
        self.writable = writable;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_flow_control_initialization() {
        let flow_control = QuicConnectionFlowControl::new();
        assert_eq!(flow_control.connection_recv_max_data, 0);
        assert_eq!(flow_control.connection_recv_window, 0);
        assert_eq!(flow_control.connection_recv_offset, 0);
        assert_eq!(flow_control.connection_send_max_data, 0);
        assert_eq!(flow_control.connection_sent_offset, 0);
        assert_eq!(flow_control.connection_sent_acked, 0);
    }

    #[test]
    fn test_connection_flow_control_set_initial_limits() {
        let mut flow_control = QuicConnectionFlowControl::new();
        flow_control.set_initial_limits(1000, 2000, 100, 50, 100, 50);

        assert_eq!(flow_control.connection_recv_max_data, 1000);
        assert_eq!(flow_control.connection_recv_window, 1000);
        assert_eq!(flow_control.connection_send_max_data, 2000);
        assert_eq!(flow_control.local_max_bidi_streams, 100);
        assert_eq!(flow_control.local_max_uni_streams, 50);
        assert_eq!(flow_control.remote_max_bidi_streams, 100);
        assert_eq!(flow_control.remote_max_uni_streams, 50);
    }

    #[test]
    fn test_connection_flow_control_recv_operations() {
        let mut flow_control = QuicConnectionFlowControl::new();
        flow_control.set_initial_limits(1000, 2000, 100, 50, 100, 50);

        assert_eq!(flow_control.get_recv_available_bytes().unwrap(), 1000);
        flow_control.increment_recv_offset(300);
        assert_eq!(flow_control.get_recv_available_bytes().unwrap(), 700);
        assert!(!flow_control.check_if_update_max_recv_data(false));
        assert!(flow_control.check_if_update_max_recv_data(true));
    }

    #[test]
    fn test_connection_flow_control_send_operations() {
        let mut flow_control = QuicConnectionFlowControl::new();
        flow_control.set_initial_limits(1000, 2000, 100, 50, 100, 50);

        assert_eq!(flow_control.get_sent_available_bytes().unwrap(), 2000);
        flow_control.increment_sent_offset(500);
        assert_eq!(flow_control.get_sent_available_bytes().unwrap(), 1500);
        flow_control.increment_sent_acked(300);
        assert_eq!(flow_control.connection_sent_acked, 300);
    }

    #[test]
    fn test_connection_flow_control_max_data_frame() {
        let mut flow_control = QuicConnectionFlowControl::new();
        flow_control.set_initial_limits(1000, 2000, 100, 50, 100, 50);

        flow_control.handle_max_data_frame(3000).unwrap();
        assert_eq!(flow_control.connection_send_max_data, 3000);

        // Should not update if new max is smaller
        flow_control.handle_max_data_frame(2500).unwrap();
        assert_eq!(flow_control.connection_send_max_data, 3000);
    }

    #[test]
    fn test_connection_flow_control_stream_counts() {
        let mut flow_control = QuicConnectionFlowControl::new();
        flow_control.set_initial_limits(1000, 2000, 100, 50, 100, 50);

        flow_control.increment_bi_stream_local();
        assert_eq!(flow_control.get_bi_stream_local_cnt(), 1);

        flow_control.increment_uni_stream_local();
        assert_eq!(flow_control.get_uni_stream_local_cnt(), 1);

        flow_control.increment_bi_stream_remote();
        assert_eq!(flow_control.get_bi_stream_remote_cnt(), 1);

        flow_control.increment_uni_stream_remote();
        assert_eq!(flow_control.get_uni_stream_remote_cnt(), 1);
    }

    #[test]
    fn test_stream_flow_control_initialization() {
        let flow_control = QuicStreamFlowControl::new(1000, 2000);
        assert_eq!(flow_control.max_send_size, 1000);
        assert_eq!(flow_control.max_recv_size, 2000);
        assert_eq!(flow_control.sent_acked, 0);
        assert_eq!(flow_control.sent_bytes, 0);
        assert_eq!(flow_control.sent_offset, 0);
        assert_eq!(flow_control.recv_offset, 0);
        assert_eq!(flow_control.recv_largest, 0);
        assert_eq!(flow_control.recv_pos, 0);
        assert_eq!(flow_control.recv_window, 2000);
        assert_eq!(flow_control.recv_final_size, None);
        assert!(flow_control.writable);
        assert!(!flow_control.readable);
    }

    #[test]
    fn test_stream_flow_control_send_operations() {
        let mut flow_control = QuicStreamFlowControl::new(1000, 2000);

        assert_eq!(flow_control.get_sent_available_bytes().unwrap(), 1000);
        flow_control.increment_sent_bytes(300);
        assert_eq!(flow_control.get_sent_available_bytes().unwrap(), 700);
        assert_eq!(flow_control.get_sent_in_flight().unwrap(), 300);

        flow_control.increment_sent_acked(200);
        assert_eq!(flow_control.get_sent_in_flight().unwrap(), 100);
    }

    #[test]
    fn test_stream_flow_control_recv_operations() {
        let mut flow_control = QuicStreamFlowControl::new(1000, 2000);

        flow_control.increment_recv_offset(300);
        assert_eq!(flow_control.get_recv_offset(), 300);

        flow_control.increment_recv_pos(200);
        assert_eq!(flow_control.get_recv_pos(), 200);

        flow_control.set_recv_largest(400);
        assert_eq!(flow_control.recv_largest, 400);
    }

    #[test]
    fn test_stream_flow_control_max_size_updates() {
        let mut flow_control = QuicStreamFlowControl::new(1000, 2000);

        flow_control.update_max_send_size(3000).unwrap();
        assert_eq!(flow_control.max_send_size, 3000);

        flow_control.update_max_recv_size(4000).unwrap();
        assert_eq!(flow_control.max_recv_size, 4000);

        // Should not update if new max is smaller
        flow_control.update_max_send_size(2500).unwrap();
        assert_eq!(flow_control.max_send_size, 3000);

        flow_control.update_max_recv_size(3500).unwrap();
        assert_eq!(flow_control.max_recv_size, 4000);
    }

    #[test]
    fn test_stream_flow_control_final_size() {
        let mut flow_control = QuicStreamFlowControl::new(1000, 2000);

        flow_control.set_recv_largest(500);
        flow_control.set_recv_final_size(1000).unwrap();
        assert_eq!(flow_control.recv_final_size, Some(1000));

        // Should error if final size is less than largest received
        assert!(flow_control.set_recv_final_size(400).is_err());

        // Should error if final size differs from previously set
        assert!(flow_control.set_recv_final_size(2000).is_err());
    }

    #[test]
    fn test_stream_flow_control_readable_writable() {
        let mut flow_control = QuicStreamFlowControl::new(1000, 2000);

        assert!(flow_control.is_writable());
        assert!(!flow_control.is_readable());

        flow_control.set_readable(true);
        assert!(flow_control.is_readable());

        flow_control.set_writable(false);
        assert!(!flow_control.is_writable());
    }
}
