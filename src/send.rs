use anyhow::Result;
use std::collections::VecDeque;
use tracing::warn;

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

    recv_cbuf_len: u64,
    store_recv_cbufs: VecDeque<(u64, Vec<u8>)>, // Sorted by first elem of tuple
    pub(crate) crypto_recv_offset: u64,
    pub(crate) crypto_send_offset: u64,
}

#[allow(dead_code)]
impl QuicSendContext {
    // TODO: Design better recv buffers for crypto and stream frame
    pub(crate) fn get_recv_cbufs_length(&self) -> u64 {
        self.store_recv_cbufs
            .iter()
            .map(|(_, b)| b.len() as u64)
            .sum()
    }

    pub(crate) fn insert_recv_cbufs(&mut self, buf: &[u8], offset: u64) {
        let pos = self
            .store_recv_cbufs
            .iter()
            .position(|(off, _)| offset < *off)
            .unwrap_or(self.store_recv_cbufs.len());
        self.store_recv_cbufs.insert(pos, (offset, buf.to_vec()));
    }

    pub(crate) fn consume_pre_recv_cbufs(&mut self, offset: u64) -> Option<Vec<u8>> {
        let mut res = vec![];
        let mut consumed_offset = offset;
        while let Some((off, buf)) = self.store_recv_cbufs.pop_front() {
            if off > consumed_offset {
                self.store_recv_cbufs.push_front((off, buf));
                return None;
            }

            let new_buf = if off != consumed_offset {
                warn!(
                    "Weird buf was sent by peer side, buf offset {}, buf len {}, expected offset {}",
                    off, buf.len(), consumed_offset
                );
                if consumed_offset >= off + buf.len() as u64 {
                    // Need to discard this useless buffer
                    return None;
                }
                let (_, right) = buf.split_at(consumed_offset as usize - off as usize);
                right
            } else {
                &buf
            };
            consumed_offset += new_buf.len() as u64;
            res.extend(new_buf);
        }

        Some(res)
    }

    pub(crate) fn need_ack(&self) -> bool {
        if self.largest_pn.is_none() {
            return false;
        }

        let lgn = self.largest_pn.unwrap();
        if self.sent_largest_acked_pn.is_none() {
            return false;
        }

        let slgan = self.sent_largest_acked_pn.unwrap();
        slgan < lgn
    }

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
