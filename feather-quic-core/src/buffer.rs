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
            write!(f, "[{}, {}], ", offset, offset + buf.len() as u64)
        })?;
        Ok(())
    }
}

impl QuicBuffer {
    pub(crate) fn insert(&mut self, buf: &[u8], offset: u64) {
        trace!(
            "Inserting receive buffer {:x?} with length {} at offset {}, bufs {:?}",
            buf,
            buf.len(),
            offset,
            self
        );
        let pos = self
            .bufs
            .iter()
            .position(|(off, _)| offset > *off)
            .unwrap_or(0);
        self.bufs.insert(pos, (offset, buf.to_vec()));

        trace!("Inserted at position {}, bufs {:?}", pos, self);
    }

    pub(crate) fn length(&self) -> u64 {
        let length = self.bufs.iter().map(|(_, b)| b.len() as u64).sum();
        trace!("Total receive buffers length: {}", length);
        length
    }

    pub(crate) fn consume(&mut self, offset: u64, len: usize) -> Option<Vec<u8>> {
        trace!(
            "Attempting to consume receive buffers {:?} from offset {}, bufs len {}",
            self,
            offset,
            len,
        );
        let mut res = vec![];
        let mut consumed_offset = offset;
        while let Some((off, buf)) = self.bufs.pop_front() {
            if off > consumed_offset {
                trace!(
                    "Buffer offset {} is ahead of consumed offset {}, returning None",
                    off,
                    consumed_offset
                );
                self.bufs.push_front((off, buf));
                return None;
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

            if (consumed_offset - offset) as usize + new_buf.len() > len {
                let (left, right) = new_buf.split_at(len);
                self.bufs.push_front((off, right.to_vec()));
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
