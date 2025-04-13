// TODO: Design better recv buffers for crypto and stream frame

use std::collections::VecDeque;
use tracing::{trace, warn};

#[derive(Default)]
pub(crate) struct QuicBuffer {
    // Sorted by first elem of tuple
    // e.g. (0, [0, 100]), (100, [100, 300]), (300, [300, 450])
    bufs: VecDeque<(u64, Vec<u8>)>,
}

impl std::fmt::Debug for QuicBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bufs.iter().try_for_each(|(offset, buf)| {
            write!(f, "[{}, {}), ", offset, offset + buf.len() as u64)
        })?;
        Ok(())
    }
}

impl QuicBuffer {
    pub(crate) fn insert(&mut self, buf: &[u8], offset: u64) {
        trace!(
            "Inserting buffer: len={}, offset={}, bufs={:?}",
            buf.len(),
            offset,
            self
        );
        let mut pos = self.bufs.len();
        let left = offset;
        let right = offset + buf.len() as u64;
        if pos == 1 && left < self.bufs[0].0 {
            pos = 0;
        }
        for i in 1..self.bufs.len() {
            let (prev_off, prev_buf) = &self.bufs[i - 1];
            let (cur_off, cur_buf) = &self.bufs[i];

            if right <= *prev_off {
                pos = i - 1;
                break;
            }

            if left >= *prev_off + prev_buf.len() as u64 && right <= *cur_off {
                pos = i;
                break;
            }

            // TODO: need to merge the overlap range
            if left >= *prev_off && right <= *cur_off + cur_buf.len() as u64 {
                pos = i - 1;
                break;
            }
        }

        self.bufs.insert(pos, (offset, buf.to_vec()));

        trace!("Inserted at position {}, bufs={:?}", pos, self);
    }

    pub(crate) fn get_recv_offset_increament_size(&self, recv_offset: u64) -> u64 {
        // Firstly recv_offset = 4436, but got [5855, 6012]
        // Then got [4436, 5854], so recv_offset is updated to 5855
        // But recv_offset should be 6012 actually
        let mut res = 0;
        let mut ro = recv_offset;
        self.bufs.iter().for_each(|(off, buf)| {
            let left = *off;
            let right = buf.len() as u64 + off;
            if ro >= left && ro < right {
                trace!("Found ro {} in [{}, {}), last res {}", ro, left, right, res);
                res += right - ro;
                ro = right;
            }
        });
        res
    }

    pub(crate) fn length(&self) -> u64 {
        let length = self.bufs.iter().map(|(_, b)| b.len() as u64).sum();
        trace!("Total receive buffers length: {}", length);
        length
    }

    pub(crate) fn consume(&mut self, offset: u64, len: usize) -> Option<Vec<u8>> {
        trace!(
            "Consuming buffers: offset={}, len={}, bufs={:?}",
            offset,
            len,
            self
        );
        let mut res = vec![];
        let mut consumed_offset = offset;
        while let Some((off, buf)) = self.bufs.pop_front() {
            if off > consumed_offset {
                trace!(
                    "Buffer offset {} is ahead of consumed offset {}",
                    off,
                    consumed_offset
                );
                self.bufs.push_front((off, buf));
                break;
            }

            let new_buf = if off != consumed_offset {
                warn!(
                    "Weird buf was sent by peer side, buf offset {}, buf len {}, expected offset {}",
                    off, buf.len(), consumed_offset
                );
                if consumed_offset >= off + buf.len() as u64 {
                    // Discard this useless buffer
                    warn!("Skip the useless buffer off {}, len {}", off, buf.len());
                    continue;
                }
                let (_, right) = buf.split_at(consumed_offset as usize - off as usize);
                right
            } else {
                &buf
            };

            let consumed_bytes = consumed_offset - offset;
            let remaining_bytes = len - consumed_bytes as usize;
            if new_buf.len() > remaining_bytes {
                let (left, right) = new_buf.split_at(remaining_bytes);
                self.bufs
                    .push_front((off + remaining_bytes as u64, right.to_vec()));
                res.extend(left);
                break;
            } else {
                consumed_offset += new_buf.len() as u64;
                res.extend(new_buf);
            }
        }

        trace!("Consumed {} bytes from buffers {:?}", res.len(), self);
        if res.is_empty() {
            None
        } else {
            Some(res)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert() {
        let mut buffer = QuicBuffer::default();

        // Insert a buffer at offset 0
        buffer.insert(&[1, 2, 3], 0);
        assert_eq!(buffer.bufs.len(), 1);
        assert_eq!(buffer.bufs[0].0, 0);
        assert_eq!(buffer.bufs[0].1, vec![1, 2, 3]);

        // Insert a buffer at offset 10
        buffer.insert(&[4, 5, 6], 10);
        assert_eq!(buffer.bufs.len(), 2);
        assert_eq!(buffer.bufs[1].0, 10);
        assert_eq!(buffer.bufs[1].1, vec![4, 5, 6]);

        // Insert a buffer at offset 5 (between the two existing buffers)
        buffer.insert(&[7, 8, 9], 5);
        assert_eq!(buffer.bufs.len(), 3);
        assert_eq!(buffer.bufs[1].0, 5);
        assert_eq!(buffer.bufs[1].1, vec![7, 8, 9]);
    }

    #[test]
    fn test_get_recv_offset_increament_size() {
        let mut buffer = QuicBuffer::default();

        // Insert buffers at offsets 0, 10, and 20
        buffer.insert(&[1, 2, 3], 0);
        buffer.insert(&[4, 5, 6], 10);
        buffer.insert(&[7, 8, 9], 20);

        // Test with recv_offset at the beginning of a buffer
        assert_eq!(buffer.get_recv_offset_increament_size(0), 3);

        // Test with recv_offset in the middle of a buffer
        assert_eq!(buffer.get_recv_offset_increament_size(11), 2);

        // Test with recv_offset at the end of a buffer
        assert_eq!(buffer.get_recv_offset_increament_size(13), 0);

        // Test with recv_offset beyond all buffers
        assert_eq!(buffer.get_recv_offset_increament_size(30), 0);
    }

    #[test]
    fn test_length() {
        let mut buffer = QuicBuffer::default();

        // Empty buffer should have length 0
        assert_eq!(buffer.length(), 0);

        // Insert buffers and check total length
        buffer.insert(&[1, 2, 3], 0);
        assert_eq!(buffer.length(), 3);

        buffer.insert(&[4, 5, 6], 10);
        assert_eq!(buffer.length(), 6);

        buffer.insert(&[7, 8, 9], 20);
        assert_eq!(buffer.length(), 9);
    }

    #[test]
    fn test_consume() {
        let mut buffer = QuicBuffer::default();

        // Insert buffers at offsets 0, 10, and 20
        buffer.insert(&[1, 2, 3], 0);
        buffer.insert(&[4, 5, 6], 10);
        buffer.insert(&[7, 8, 9], 20);

        // Consume from the beginning
        let consumed = buffer.consume(0, 3).unwrap();
        assert_eq!(consumed, vec![1, 2, 3]);
        assert_eq!(buffer.bufs.len(), 2);

        // Consume from the middle
        let consumed = buffer.consume(10, 2).unwrap();
        assert_eq!(consumed, vec![4, 5]);
        assert_eq!(buffer.bufs.len(), 2);

        // After consuming [4, 5], the buffer at offset 10 now only contains [6]
        // Let's consume just that one byte
        let consumed = buffer.consume(12, 1).unwrap();
        assert_eq!(consumed, vec![6]);
        assert_eq!(buffer.bufs.len(), 1);

        // Now consume from the next buffer
        let consumed = buffer.consume(20, 3).unwrap();
        assert_eq!(consumed, vec![7, 8, 9]);
        assert_eq!(buffer.bufs.len(), 0);

        // Consume from empty buffer
        let consumed = buffer.consume(20, 1);
        assert_eq!(consumed, None);
    }

    #[test]
    fn test_consume_with_gaps() {
        let mut buffer = QuicBuffer::default();

        // Insert buffers with gaps
        buffer.insert(&[1, 2, 3], 0);
        buffer.insert(&[7, 8, 9], 10);

        // Consume from the beginning
        let consumed = buffer.consume(0, 3).unwrap();
        assert_eq!(consumed, vec![1, 2, 3]);
        assert_eq!(buffer.bufs.len(), 1);

        // Consume from the second buffer
        let consumed = buffer.consume(10, 3).unwrap();
        assert_eq!(consumed, vec![7, 8, 9]);
        assert_eq!(buffer.bufs.len(), 0);

        // Consume from empty buffer
        let consumed = buffer.consume(0, 1);
        assert_eq!(consumed, None);
    }
}
