use anyhow::{anyhow, Result};
use std::collections::{HashSet, VecDeque};
use std::ops::ControlFlow;
use std::time::{Duration, Instant};
use tracing::{error, info, trace, warn};

use crate::ack::{QuicAckGenerator, QuicAckRange};
use crate::connection::QuicLevel;
use crate::frame::{QuicFrame, QuicPing};
use crate::rtt::QuicRttGenerator;

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

    pub(crate) ack_generator: QuicAckGenerator,
    packet_threshold: Option<u16>,

    recv_cbuf_len: u64,
    store_recv_cbufs: VecDeque<(u64, Vec<u8>)>, // Sorted by first elem of tuple
    pub(crate) crypto_recv_offset: u64,
    pub(crate) crypto_send_offset: u64,
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.1
const QUIC_PACKET_THRESHOLD: u16 = 3;

#[allow(dead_code)]
impl QuicSendContext {
    // TODO: Design better recv buffers for crypto and stream frame
    pub(crate) fn get_recv_cbufs_length(&self) -> u64 {
        let length = self
            .store_recv_cbufs
            .iter()
            .map(|(_, b)| b.len() as u64)
            .sum();
        trace!("Total receive crypto buffers length: {}", length);
        length
    }

    pub(crate) fn insert_recv_cbufs(&mut self, buf: &[u8], offset: u64) {
        trace!(
            "Inserting receive crypto buffer with length {} at offset {}",
            buf.len(),
            offset
        );
        let pos = self
            .store_recv_cbufs
            .iter()
            .position(|(off, _)| offset < *off)
            .unwrap_or(self.store_recv_cbufs.len());
        self.store_recv_cbufs.insert(pos, (offset, buf.to_vec()));
        trace!(
            "Inserted at position {}, total buffers: {}",
            pos,
            self.store_recv_cbufs.len()
        );
    }

    pub(crate) fn clear(&mut self, level: QuicLevel) -> Result<()> {
        if !self.sent_queue.is_empty() {
            warn!(
                "{:?} sent queue is not empty {}",
                level,
                self.sent_queue.len()
            );
            self.sent_queue.clear();
        }

        if !self.send_queue.is_empty() {
            warn!(
                "{:?} send queue is not empty {}",
                level,
                self.send_queue.len()
            );
            self.send_queue.clear();
        }

        Ok(())
    }

    pub(crate) fn consume_pre_recv_cbufs(&mut self, offset: u64) -> Option<Vec<u8>> {
        trace!(
            "Attempting to consume receive crypto buffers from offset {}",
            offset
        );
        let mut res = vec![];
        let mut consumed_offset = offset;
        while let Some((off, buf)) = self.store_recv_cbufs.pop_front() {
            if off > consumed_offset {
                trace!(
                    "Buffer offset {} is ahead of consumed offset {}, returning None",
                    off,
                    consumed_offset
                );
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

        trace!("Consumed {} bytes from crypto buffers", res.len());
        Some(res)
    }

    pub(crate) fn need_ack(&self, current_ts: &Instant, local_mad: u16) -> bool {
        let need = self.ack_generator.need_ack(current_ts, local_mad);
        trace!(
            "Checking if ACK is needed: {}, details {}",
            need,
            self.ack_generator
        );
        need
    }

    pub(crate) fn reset_ack(&mut self) {
        trace!("Resetting ACK generator");
        self.ack_generator.reset_ack();
    }

    pub(crate) fn get_single_ack_pns(&self) -> Option<&HashSet<u64>> {
        self.ack_generator.get_single_ack_pns()
    }

    pub(crate) fn get_ack_delay_start_time(&self) -> Option<&Instant> {
        self.ack_generator.get_ack_delay_start_time()
    }

    pub(crate) fn get_top_range(&self) -> Option<u64> {
        self.ack_generator.get_top_range()
    }

    pub(crate) fn get_first_range(&self) -> u64 {
        self.ack_generator.get_first_range()
    }

    pub(crate) fn get_ranges(&self) -> VecDeque<QuicAckRange> {
        self.ack_generator.get_ranges()
    }

    pub(crate) fn get_next_packet_number(&self) -> u64 {
        self.next_pn
    }

    pub(crate) fn consume_send_queue(&mut self) -> Option<QuicFrame> {
        let frame = self.send_queue.pop_front();
        if let Some(ref f) = frame {
            trace!("Consuming frame from send queue: {:?}", f);
        }
        frame
    }

    pub(crate) fn is_send_queue_empty(&self) -> bool {
        self.send_queue.is_empty()
    }

    // for high priority QUIC frame
    pub(crate) fn insert_send_queue_front(&mut self, f: QuicFrame) {
        trace!("Inserting frame to front of send queue: {:?}", f);
        self.send_queue.push_front(f);
    }

    pub(crate) fn insert_send_queue_back(&mut self, f: QuicFrame) {
        trace!("Inserting frame to back of send queue: {:?}", f);
        self.send_queue.push_back(f);
    }

    pub(crate) fn insert_sent_queue_back(&mut self, f: QuicFrame) {
        trace!("Inserting frame to sent queue: {:?}", f);
        self.sent_queue.push_back(f);
    }

    pub(crate) fn extend_send_queue_front(&mut self, v: VecDeque<QuicFrame>) {
        v.into_iter().for_each(|f| self.send_queue.push_front(f));
    }

    pub(crate) fn extend_send_queue_back(&mut self, v: VecDeque<QuicFrame>) {
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

    pub(crate) fn generate_ack(&mut self) -> Result<()> {
        Ok(())
    }

    pub(crate) fn calculate_loss(&mut self, time_threshold: Duration) -> Result<Option<Instant>> {
        if let Some(first) = self.sent_queue.front() {
            let pn = first
                .get_packet_number()
                .ok_or_else(|| anyhow!("Frame must have packet number {:?}", first))?;

            // The packet is unacknowledged, in flight, and was sent prior to an acknowledged packet.
            let largest_acked = if let Some(la) = self.largest_acked {
                la
            } else {
                return Ok(None);
            };

            if pn > largest_acked {
                return Ok(None);
            }

            let send_time = first
                .get_send_time()
                .ok_or_else(|| anyhow!("Frame must have send time {:?}", first))?;

            Ok(Some(send_time + time_threshold))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn detect_lost(
        &mut self,
        rtt: &QuicRttGenerator,
        current_ts: Instant,
    ) -> Result<bool> {
        trace!("Starting packet loss detection at {:?}", current_ts);

        // Acknowledgement-Based Detection
        // https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1

        let largest_acked = if let Some(la) = self.largest_acked {
            la
        } else {
            // The packet is unacknowledged, in flight, and was sent prior to an acknowledged packet.
            info!("Ack frame has not been received yet, skip the lost detection");
            return Ok(false);
        };

        let time_threshold = rtt.get_time_threhold();

        let mut split_index = None;
        self.sent_queue.iter().try_for_each(|f| {
            if matches!(f, QuicFrame::Ack(_)) {
                return ControlFlow::Continue(());
            }

            let pn = if let Some(pn) = f.get_packet_number() {
                pn
            } else {
                error!(
                    "Frame in the sent queue must have the packet number {:?}",
                    f
                );
                return ControlFlow::Break(());
            };

            if pn > largest_acked {
                trace!(
                    "The {} packet should be sent prior to an acknowledged packet {}",
                    pn,
                    largest_acked
                );
                return ControlFlow::Break(());
            }

            let send_time = if let Some(send_time) = f.get_send_time() {
                send_time
            } else {
                error!("Frame in the sent queue must have the send_time {:?}", f);
                return ControlFlow::Break(());
            };

            let packets_threshold = self.packet_threshold.unwrap_or(QUIC_PACKET_THRESHOLD);

            // The packet was sent kPacketThreshold packets before an acknowledged packet (Section 6.1.1),
            // or it was sent long enough in the past
            if pn < largest_acked.saturating_sub(packets_threshold as u64)
                && send_time + time_threshold > current_ts
            {
                return ControlFlow::Break(());
            }

            split_index = Some(split_index.unwrap_or(0) + 1);

            ControlFlow::Continue(())
        });

        trace!(
            "Detect Lost, split_index {:?}, time_threshold {:?}",
            split_index,
            time_threshold
        );

        // https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        if let Some(mut index) = split_index {
            trace!("Found {} potentially lost packets", index);
            while index > 0 {
                let mut frame = self.sent_queue.pop_front().ok_or_else(|| {
                    anyhow!("Must have the frame in the sent queue, count {}", index)
                })?;
                if matches!(frame, QuicFrame::Ack(_)) || matches!(frame, QuicFrame::Ping(_)) {
                    trace!("Drop the frame {:?} from the sent queue", frame);
                    continue;
                }
                trace!("Moving lost frame back to send queue: {:?}", frame);
                frame.clear_frame_common();
                index -= 1;
                self.insert_send_queue_front(frame);
            }
        }

        Ok(split_index.is_some())
    }

    pub(crate) fn resend_first_eliciting_frame(&mut self) -> bool {
        let mut found = false;
        while let Some(mut frame) = self.sent_queue.pop_front() {
            if matches!(frame, QuicFrame::Ack(_)) || matches!(frame, QuicFrame::Ping(_)) {
                trace!("Drop the frame {:?} from the sent queue", frame);
                continue;
            }
            trace!("Retransmit lost frame back to send queue: {:?}", frame);
            found = true;
            frame.clear_frame_common();
            self.insert_send_queue_front(frame);
        }
        found
    }

    pub(crate) fn create_and_insert_ping_frame(&mut self) -> Result<()> {
        let ping_frame = QuicFrame::Ping(QuicPing::default());
        self.insert_send_queue_front(ping_frame);
        trace!("Now we are creating ping frame");

        Ok(())
    }

    pub(crate) fn resend_all(&mut self) -> Result<()> {
        while let Some(mut f) = self.sent_queue.pop_front() {
            f.clear_frame_common();
            self.send_queue.push_front(f);
        }

        Ok(())
    }

    fn handle_ack_range(
        &mut self,
        smallest: u64,
        largest: u64,
        get_send_time: bool,
    ) -> Result<(bool, Option<Instant>)> {
        trace!(
            "Processing ACK range [{}..{}], get_send_time: {}",
            smallest,
            largest,
            get_send_time
        );
        let mut ackeliciting_packet_acked = false;
        let mut send_time = None;
        self.sent_queue.retain(|f| {
            let pn = if let Some(pn) = f.get_packet_number() {
                pn
            } else {
                error!("Frame {:?} must have the packet number!", f);
                return false;
            };

            if pn > largest {
                return true;
            }

            if pn >= smallest {
                match f {
                    QuicFrame::Ack(frame) => {
                        // Clean the Acked frames in sent queue
                        // and retire the old ack ranges in the ack generator
                        self.ack_generator
                            .drop_ack_ranges(frame.get_largest_acknowledged());
                    }
                    QuicFrame::Stream(_) => unimplemented!(),
                    _ => {
                        trace!("The frame {:?} is acked!", f);
                    }
                }
                if pn == largest && get_send_time {
                    send_time = f.get_send_time();
                    trace!("Get the acked largest packet sent time {:?}", send_time);
                }

                return false;
            }
            if f.is_ack_eliciting() {
                ackeliciting_packet_acked = true;
            }
            true
        });

        if largest >= self.next_pn {
            // TODO: QUIC connection termination
            return Err(anyhow!(
                "Received invalid ack frame, never sent this packet {}, current pn {}",
                largest,
                self.next_pn
            ));
        }

        Ok((ackeliciting_packet_acked, send_time))
    }

    pub(crate) fn calculate_pto(
        &mut self,
        pto_time: Duration,
        level: QuicLevel,
        check_eliciting: bool,
    ) -> Result<Option<Instant>> {
        trace!(
            "Calculating {:?} PTO with duration {:?}, sent queue size {}",
            level,
            pto_time,
            self.sent_queue.len()
        );
        let mut pto = None;
        let iter = self.sent_queue.iter();
        for f in iter {
            trace!("Loop the sent queue in {:?} space, {:?}", level, f);
            if check_eliciting && !f.is_ack_eliciting() {
                continue;
            }
            let send_time = f
                .get_send_time()
                .ok_or_else(|| anyhow!("Frame must have send time {:?}", f))?;

            pto = Some(send_time + pto_time);
            trace!("PTO calculated: {:?}", pto);
            break;
        }
        Ok(pto)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_ack_frame(
        &mut self,
        first_range: u64,
        top_range: u64,
        ranges: &[QuicAckRange],
        rtt: &mut QuicRttGenerator,
        level: QuicLevel,
        current_ts: &Instant,
        delay: u64,
    ) -> Result<()> {
        let mut largest = top_range;
        let mut smallest = top_range.checked_sub(first_range).ok_or_else(|| {
            anyhow!(
                "The top_range {} must be larger then first_range {}",
                top_range,
                first_range
            )
        })?;

        let mut largest_acked_updated = false;
        let mut ackeliciting_packet_acked = false;

        if let Some(lgna) = self.largest_acked.as_mut() {
            if *lgna < top_range {
                *lgna = top_range;
                largest_acked_updated = true;
            }
        } else {
            trace!(
                "Processing ack frame, largest_acked was updated to {}",
                top_range
            );
            self.largest_acked = Some(top_range);
        }

        let mut index = 0;
        let mut sent_time = None;
        loop {
            let get_send_time = largest_acked_updated && largest == top_range;
            let (acked, send_time) = self.handle_ack_range(smallest, largest, get_send_time)?;
            ackeliciting_packet_acked |= acked;
            if get_send_time && send_time.is_none() {
                warn!("Should get our send time here for no.{top_range} packet");
            }
            if sent_time.is_none() {
                sent_time = send_time;
            }

            if index >= ranges.len() {
                break;
            }

            largest = smallest
                .checked_sub(ranges[index].get_gap() + 2)
                .ok_or_else(|| {
                    anyhow!(
                        "The smallest {} must be larger then next gap {}",
                        smallest,
                        ranges[index].get_gap()
                    )
                })?;
            smallest = largest
                .checked_sub(ranges[index].get_ack_range_length())
                .ok_or_else(|| {
                    anyhow!(
                        "The largest {} must be larger then cur ack range length {}",
                        largest,
                        ranges[index].get_ack_range_length()
                    )
                })?;
            index += 1;
        }

        // https://www.rfc-editor.org/rfc/rfc9002.html#name-estimating-the-round-trip-t
        // An endpoint generates an RTT sample on receiving an ACK frame that meets the following two conditions:
        //      1. the largest acknowledged packet number is newly acknowledged, and
        //      2. at least one of the newly acknowledged packets was ack-eliciting.
        if largest_acked_updated && ackeliciting_packet_acked {
            if let Some(sent_time) = sent_time {
                let latest_rtt =
                    sent_time
                        .checked_duration_since(*current_ts)
                        .ok_or_else(|| {
                            anyhow!(
                                "Current ts {:?} must be larger then sent_time {:?}",
                                current_ts,
                                sent_time
                            )
                        })?;
                rtt.update(level, delay, latest_rtt)?;
            }
        }

        Ok(())
    }

    pub(crate) fn update_ack(
        &mut self,
        pn: u64,
        need_ack: bool,
        now: &Instant,
        level: QuicLevel,
    ) -> Result<bool> {
        let should_ack = self.ack_generator.update_ack(pn, need_ack, now, level)?;
        // Single old packet should be acked sperately

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.3
        // Managing ACK ranges
        // ACK frames SHOULD always acknowledge the most recently received packets,
        // and the more out of order the packets are, the more important it is to send an updated ACK frame quickly
        // An ACK frame is expected to fit within a single QUIC packet.
        // If it does not, then older ranges (those with the smallest packet numbers) are omitted.

        self.largest_pn = self.largest_pn.map_or(Some(pn), |lpn| Some(pn.max(lpn)));

        trace!(
            "Update {:?} packet space pn {}, largest_pn {:?}, is_ack_eliciting {}, should_ack {}",
            level,
            pn,
            self.largest_pn,
            need_ack,
            should_ack
        );

        Ok(should_ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::QuicAck;
    use std::time::Duration;

    fn setup_test_context() -> QuicSendContext {
        QuicSendContext {
            next_pn: 100, // Set initial packet number
            ..Default::default()
        }
    }

    #[test]
    fn test_handle_ack_frame_basic() {
        let mut ctx = setup_test_context();
        let mut rtt = QuicRttGenerator::default();
        let current_ts = Instant::now();

        // Add some frames to sent queue
        let mut frame1 = QuicFrame::Ping(QuicPing::default());
        frame1.set_packet_number(95);
        frame1.set_send_time(current_ts - Duration::from_secs(1));

        let mut frame2 = QuicFrame::Ping(QuicPing::default());
        frame2.set_packet_number(96);
        frame2.set_send_time(current_ts - Duration::from_secs(1));

        ctx.sent_queue.push_back(frame1);
        ctx.sent_queue.push_back(frame2);

        // Test basic ACK frame handling
        let result = ctx.handle_ack_frame(
            1,   // first_range
            96,  // top_range
            &[], // no additional ranges
            &mut rtt,
            QuicLevel::Initial,
            &current_ts,
            1000, // delay in microseconds
        );

        assert!(result.is_ok());
        assert_eq!(ctx.largest_acked, Some(96));
        assert_eq!(ctx.sent_queue.len(), 0); // All frames should be acknowledged
    }

    #[test]
    fn test_handle_ack_frame_with_ranges() {
        let mut ctx = setup_test_context();
        let mut rtt = QuicRttGenerator::default();
        let current_ts = Instant::now();

        // Add frames to sent queue with different packet numbers
        for pn in [95, 96, 97, 98, 99].iter() {
            let mut frame = QuicFrame::Ping(QuicPing::default());
            frame.set_packet_number(*pn);
            frame.set_send_time(current_ts - Duration::from_secs(1));
            ctx.sent_queue.push_back(frame);
        }

        // Create ACK ranges: [98-99], [95-96]
        let ranges = vec![
            QuicAckRange::new(0, 1), // Gap: 0, Length: 1 for packet 95-96
        ];

        let result = ctx.handle_ack_frame(
            1,  // first_range (98-99)
            99, // top_range
            &ranges,
            &mut rtt,
            QuicLevel::Initial,
            &current_ts,
            1000,
        );

        assert!(result.is_ok());
        assert_eq!(ctx.largest_acked, Some(99));
        assert_eq!(ctx.sent_queue.len(), 1); // Only packet 97 should remain unacked
    }

    #[test]
    fn test_handle_ack_frame_invalid_range() {
        let mut ctx = setup_test_context();
        let mut rtt = QuicRttGenerator::default();
        let current_ts = Instant::now();

        // Test with invalid range where top_range is less than first_range
        let result = ctx.handle_ack_frame(
            10, // first_range larger than top_range
            5,  // top_range
            &[],
            &mut rtt,
            QuicLevel::Initial,
            &current_ts,
            1000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_ack_frame_rtt_update() {
        let mut ctx = setup_test_context();
        let mut rtt = QuicRttGenerator::default();
        let current_ts = Instant::now();

        // Add an ack-eliciting frame
        let mut frame = QuicFrame::Ping(QuicPing::default());
        frame.set_packet_number(95);
        frame.set_send_time(current_ts - Duration::from_secs(1));
        ctx.sent_queue.push_back(frame);

        let result = ctx.handle_ack_frame(
            0,  // first_range
            95, // top_range
            &[],
            &mut rtt,
            QuicLevel::Initial,
            &current_ts,
            1000,
        );

        assert!(result.is_ok());
        // RTT should be updated since we received an ACK for an ack-eliciting packet
        assert!(rtt.get_rtt() > Duration::from_secs(0));
    }

    #[test]
    fn test_handle_ack_frame_multiple_packets() {
        let mut ctx = setup_test_context();
        let mut rtt = QuicRttGenerator::default();
        let current_ts = Instant::now();

        // Add multiple frames with different types
        let mut ping_frame = QuicFrame::Ping(QuicPing::default());
        ping_frame.set_packet_number(95);
        ping_frame.set_send_time(current_ts - Duration::from_secs(1));

        // Create an ACK frame with specific ranges
        let mut ack_frame = QuicFrame::Ack(QuicAck::new(90, 1000, 0, 0, Some(VecDeque::new())));
        ack_frame.set_packet_number(96);
        ack_frame.set_send_time(current_ts - Duration::from_secs(1));

        ctx.sent_queue.push_back(ping_frame);
        ctx.sent_queue.push_back(ack_frame);

        let result = ctx.handle_ack_frame(
            1,  // first_range
            96, // top_range
            &[],
            &mut rtt,
            QuicLevel::Initial,
            &current_ts,
            1000,
        );

        assert!(result.is_ok());
        assert_eq!(ctx.sent_queue.len(), 0);
        assert_eq!(ctx.largest_acked, Some(96));
    }
}
