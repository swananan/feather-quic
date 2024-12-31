use anyhow::Result;
use std::collections::VecDeque;

use crate::frame::QuicFrame;

#[allow(dead_code)]
#[derive(Default)]
pub(crate) struct QuicSendContext {
    // These fields are used for storing info from peer Ack frame
    // largest_pn is the largest packet number that has been successfully processed in the current packet number space.
    pub(crate) largest_pn: Option<u64>,
    // largest_acked is the largest packet number that has been acknowledged by the peer in the current packet number space, if any.
    pub(crate) largest_acked: Option<u64>,

    // Send or Sent queue
    pub(crate) send_queue: VecDeque<QuicFrame>,
    pub(crate) sent_queue: VecDeque<QuicFrame>,

    // These fields are used for contruct Ack frame or QUIC packet
    pub(crate) next_pn: u64,
    pub(crate) sent_largest_acked_pn: Option<u64>,

    pub(crate) crypto_recv_offset: u64,
    pub(crate) crypto_send_offset: u64,
}

#[allow(dead_code)]
impl QuicSendContext {
    pub(crate) fn get_next_packet_number(&self) -> u64 {
        self.next_pn
    }

    pub(crate) fn consume_send_queue(&mut self) -> Option<QuicFrame> {
        self.send_queue.pop_front()
    }

    pub(crate) fn is_send_queue_empty(&self) -> bool {
        self.send_queue.is_empty()
    }

    // for high priority QUIC frame
    pub(crate) fn insert_send_queue_front(&mut self, f: QuicFrame) {
        self.send_queue.push_front(f);
    }

    pub(crate) fn insert_send_queue_back(&mut self, f: QuicFrame) {
        self.send_queue.push_back(f);
    }

    pub(crate) fn extend_sent_queue_back(&mut self, v: VecDeque<QuicFrame>) {
        self.send_queue.extend(v);
    }

    pub(crate) fn insert_send_queue_with_crypto_data(
        &mut self,
        crypto_data: Vec<u8>,
    ) -> Result<()> {
        if let Some(crypto_frame) = QuicFrame::create_crypto_frame(self, crypto_data)? {
            self.insert_send_queue_back(crypto_frame);
        }
        Ok(())
    }
}
