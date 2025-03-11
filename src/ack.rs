use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::fmt::Display;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

use crate::connection::QuicLevel;
use crate::utils::format_instant;

#[derive(Debug, Clone)]
pub(crate) struct QuicAckRange {
    gap: u64,
    ack_range_length: u64,
}

impl QuicAckRange {
    pub(crate) fn new(gap: u64, ack_range_length: u64) -> Self {
        Self {
            gap,
            ack_range_length,
        }
    }

    pub(crate) fn get_gap(&self) -> u64 {
        self.gap
    }

    pub(crate) fn get_ack_range_length(&self) -> u64 {
        self.ack_range_length
    }
}

// A receiver SHOULD send an ACK frame after receiving at least two ack-eliciting packets.
// This recommendation is general in nature and consistent with recommendations for TCP endpoint behavior [RFC5681]
const QUIC_ACK_MAX_COUNT: u32 = 2;
const QUIC_MAX_RANGES: usize = 18;

#[derive(Default)]
pub(crate) struct QuicAckGenerator {
    // How to arrange the received Packets:
    // ... [largest - ack_range, largest = previous_smallest - gap - 2] [top_range - first_range, top_range]
    first_range: u64,
    top_range: Option<u64>,
    ranges: VecDeque<QuicAckRange>,
    ack_delay_start: Option<Instant>,
    ack_count: u32,
    ack_single_pns: Option<HashSet<u64>>,
    max_ranges: Option<usize>,
    ack_max_count: Option<u32>,
}

impl Display for QuicAckGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ack_delay_start {:?}, ack_count {}, first_range {}, top_range {:?}, the first range [{:?}, {:?}], ",
            self.ack_delay_start,
            self.ack_count,
            self.first_range,
            self.top_range,
            self.top_range.map(|r| r - self.first_range),
            self.top_range,
        )?;

        let mut previous_smallest = self.top_range.unwrap_or(0) - self.first_range;
        self.ranges.iter().try_for_each(|r| {
            let largest = previous_smallest - r.gap - 2;
            let smallest = largest - r.ack_range_length;
            previous_smallest = smallest;
            write!(f, "[{}, {}], ", smallest, largest)
        })?;
        Ok(())
    }
}
impl QuicAckGenerator {
    pub(crate) fn get_ack_delay_start_time(&self) -> Option<&Instant> {
        self.ack_delay_start.as_ref()
    }

    pub(crate) fn get_single_ack_pns(&self) -> Option<&HashSet<u64>> {
        self.ack_single_pns.as_ref()
    }

    pub(crate) fn get_top_range(&self) -> Option<u64> {
        self.top_range
    }

    pub(crate) fn get_first_range(&self) -> u64 {
        self.first_range
    }

    pub(crate) fn get_ranges(&self) -> VecDeque<QuicAckRange> {
        self.ranges.clone()
    }

    pub(crate) fn need_ack(&self, current_ts: &Instant, local_mad: u16) -> bool {
        let ack_max = self.ack_max_count.unwrap_or(QUIC_ACK_MAX_COUNT);
        if self.ack_count >= ack_max {
            return true;
        }

        match self.ack_delay_start {
            Some(ds) if self.ack_count > 0 && *current_ts > ds => {
                trace!(
                    "The gap of ack delay is {}",
                    format_instant(ds, *current_ts)
                );
                (*current_ts - ds) >= Duration::from_millis(local_mad as u64)
            }
            _ => false,
        }
    }

    pub(crate) fn reset_ack(&mut self) {
        self.ack_count = 0;
        self.ack_single_pns = None;
        self.ack_delay_start = None;
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-limiting-ranges-by-tracking
    // The reason the we want to remove all packet numbers less than or equal to
    // the largest packet number in an ACK_FRAME when that frame is acknowledged
    // is because we make the assumption that by the time it gets that
    // acknowledgment, everything in that range was either completely lost or
    // included in the ACK_FRAME and has been acknowledged. (commemts from MsQUIC)
    pub(crate) fn drop_ack_ranges(&mut self, pn: u64) {
        trace!("Start to drop ack, largest_acked {}, ranges {}", pn, self);

        if self.top_range.is_none() {
            return;
        }

        let mut largest = self.top_range.unwrap();
        let mut smallest = largest - self.first_range;

        if pn >= largest {
            self.top_range = None;
            self.first_range = 0;
            self.ranges.clear();
            return;
        }

        if pn >= smallest {
            self.first_range = largest - pn - 1;
            self.ranges.clear();
            return;
        }

        let mut index = 0;
        for (i, r) in self.ranges.iter_mut().enumerate() {
            largest = smallest - r.gap - 2;
            smallest = largest - r.ack_range_length;
            if pn >= largest {
                index = i;
                break;
            }

            if pn >= smallest {
                r.ack_range_length = largest - pn - 1;
                index = i + 1;
                break;
            }
            index = i;
        }

        self.ranges.truncate(index);

        trace!(
            "Finished the ack droping, largest_acked {}, ranges {}",
            pn,
            self
        );
    }

    pub(crate) fn update_ack(
        &mut self,
        pn: u64,
        need_ack: bool,
        now: &Instant,
        level: QuicLevel,
    ) -> Result<bool> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.1-7
        // The scenarios which receiver should send an ACK frame without delay

        let mut should_ack = false;
        let ack_max_count: u32 = self.ack_max_count.unwrap_or(QUIC_ACK_MAX_COUNT);

        trace!(
            "Start to update ack, need_ack {}, pn {}, ack_count {}, level {:?}, ranges {}",
            need_ack,
            pn,
            self.ack_count,
            level,
            self
        );

        if need_ack {
            self.ack_count += 1;
            if self.ack_count >= ack_max_count {
                should_ack = true;
            }

            if level != QuicLevel::Application {
                should_ack = true;
                self.ack_count = ack_max_count;
            }

            if self.ack_delay_start.is_none() {
                self.ack_delay_start = Some(*now);
                trace!("Update ack_delay_start to {:?}", now);
            }
        }

        let top_range = if let Some(t) = self.top_range {
            t
        } else {
            trace!(
                "Updated top range {:?} to pn {}, should_ack {}, ack_count {}, ranges {}",
                self.top_range,
                pn,
                should_ack,
                self.ack_count,
                self
            );
            self.top_range = Some(pn);
            return Ok(should_ack);
        };

        if pn == top_range {
            info!("Received duplicated pakcet pn {}", pn);
            return Ok(should_ack);
        }

        // First range: [top_range - first_range, top_range]
        let mut largest = top_range;
        let mut smallest = top_range - self.first_range;

        if pn > top_range {
            if pn == top_range + 1 {
                self.top_range = Some(pn);
                self.first_range += 1;
                return Ok(should_ack);
            } else {
                self.first_range = 0;
                self.top_range = Some(pn);

                // e.g. [1,2] [6,7] got 10 ==> [1,2] [4,7] [10,10]
                let gap = pn - largest - 2;
                let ack_range_length = largest - smallest;
                let max_ranges = self.max_ranges.unwrap_or(QUIC_MAX_RANGES);
                if self.ranges.len() > max_ranges {
                    warn!(
                        "Too many unacked ranges {} limit {}",
                        self.ranges.len(),
                        max_ranges
                    );
                    should_ack = true;
                    self.ack_count = ack_max_count;
                }
                self.ranges
                    .push_front(QuicAckRange::new(gap, ack_range_length));

                // https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.1-8.2
                // when the packet has a packet number larger than the highest-numbered
                // ack-eliciting packet that has been received and there are missing
                // packets between that packet and this packet.
                if need_ack {
                    trace!(
                        "Received larger out of order packet pn {} top_range {}, \
                        previous biggest range [{}, {}], ranges {:?}",
                        pn,
                        top_range,
                        smallest,
                        largest,
                        self.ranges,
                    );
                    should_ack = true;
                    self.ack_count = ack_max_count;
                }
            }
        } else {
            // Received out of order packet
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.1-8.1
            trace!(
                "Received smaller out of order packet pn {} need_ack {} top_range {}, ranges {:?}",
                pn,
                need_ack,
                top_range,
                self.ranges
            );
            if need_ack {
                should_ack = true;
                self.ack_count = ack_max_count;
            }

            // Hit in the first range
            if pn >= smallest && pn <= largest {
                return Ok(should_ack);
            }

            let mut index = 0;

            while !self.ranges.is_empty() && index < self.ranges.len() {
                let r = &mut self.ranges[index];
                let right_hole = smallest - 1;
                let left_hole = right_hole - r.gap;

                trace!(
                    "Check if index {} (r {:?}) hit in the hole [{}, {}], current range [{}, {}]",
                    index,
                    r,
                    left_hole,
                    right_hole,
                    smallest,
                    largest
                );

                // Hit in the [smallest, largest]
                if pn >= left_hole && pn <= right_hole {
                    // Merge the acked range to the previous range
                    if right_hole == left_hole {
                        // For example: [3,4] [6,8] and hole is [5,5] ==> [3,8]
                        if index > 0 {
                            self.ranges[index - 1].ack_range_length += r.ack_range_length + 2;
                        } else {
                            self.first_range += r.ack_range_length + 2;
                        }
                        self.ranges.remove(index);
                    } else if pn == left_hole {
                        // For example: [3,4] [7,8] and hole is [5,6], pn is 5 ==> [3,5] [7,8]
                        r.gap -= 1;
                        r.ack_range_length += 1;
                    } else if pn == right_hole {
                        // For example: [3,4] [7,8] and hole is [5,6], pn is 6 ==> [3,4] [6,8]
                        r.gap -= 1;
                        if index > 0 {
                            self.ranges[index - 1].ack_range_length += 1;
                        } else {
                            self.first_range += 1;
                        }
                    } else {
                        // Split the current range
                        // For example: [3,4] [8,9] and hole is [5,7], pn is 6 ==> [3,4] [6,6] [8,9]
                        let new_gap = right_hole - pn - 1;
                        r.gap = pn - left_hole - 1;
                        self.ranges.insert(index, QuicAckRange::new(new_gap, 0));
                    }
                    return Ok(should_ack);
                }

                largest = smallest - r.gap - 2;
                smallest = largest - r.ack_range_length;
                if pn >= smallest && pn <= largest {
                    return Ok(should_ack);
                }

                index += 1;
            }

            // Not hit in the ranges
            if pn == smallest - 1 {
                if !self.ranges.is_empty() {
                    let last_index = self.ranges.len() - 1;
                    self.ranges[last_index].ack_range_length += 1;
                } else {
                    self.first_range += 1;
                }
            } else if self.ranges.len() >= self.max_ranges.unwrap_or(QUIC_MAX_RANGES) {
                info!("Received a very old packet {}", pn);
                should_ack = true;
                if let Some(pns) = self.ack_single_pns.as_mut() {
                    pns.insert(pn);
                } else {
                    let mut s = HashSet::new();
                    s.insert(pn);
                    self.ack_single_pns = Some(s);
                }
            } else {
                self.ranges
                    .push_back(QuicAckRange::new(smallest - 2 - pn, 0));
            }
        }

        trace!(
            "Updated ack ranges, need_ack {}, pn {}, should_ack {}, ack_count {}, \
            ranges {:?}, self {}",
            need_ack,
            pn,
            should_ack,
            self.ack_count,
            self.ranges,
            self
        );

        Ok(should_ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Once;
    #[allow(unused)]
    static TRACING: Once = Once::new();

    #[allow(dead_code)]
    fn init_tracing() {
        TRACING.call_once(|| {
            let env_filter = tracing_subscriber::EnvFilter::from_default_env();
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        });
    }

    #[test]
    fn test_update_ack_sequential() {
        // init_tracing();
        let mut gen = QuicAckGenerator::default();
        let now = Instant::now();

        // Test sequential packet numbers
        assert!(!gen
            .update_ack(1, true, &now, QuicLevel::Application)
            .unwrap());
        assert_eq!(gen.get_top_range(), Some(1));
        assert_eq!(gen.get_first_range(), 0);

        // Second packet should trigger ACK due to QUIC_ACK_MAX_COUNT
        assert!(gen
            .update_ack(2, true, &now, QuicLevel::Application)
            .unwrap());
        assert_eq!(gen.get_top_range(), Some(2));
        assert_eq!(gen.get_first_range(), 1);

        assert!(gen
            .update_ack(3, true, &now, QuicLevel::Application)
            .unwrap());
        assert_eq!(gen.get_top_range(), Some(3));
        assert_eq!(gen.get_first_range(), 2);
    }

    #[test]
    fn test_update_ack_out_of_order() {
        let mut gen = QuicAckGenerator::default();
        let now = Instant::now();

        // Test out of order packets
        assert!(!gen
            .update_ack(5, true, &now, QuicLevel::Application)
            .unwrap());
        assert!(gen
            .update_ack(3, true, &now, QuicLevel::Application)
            .unwrap()); // Should trigger immediate ACK

        assert_eq!(gen.get_top_range(), Some(5));
        assert_eq!(gen.get_first_range(), 0);

        let ranges = gen.get_ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].get_gap(), 0);
        assert_eq!(ranges[0].get_ack_range_length(), 0);
    }

    #[test]
    fn test_need_ack_with_delay() {
        let mut gen = QuicAckGenerator::default();
        let start = Instant::now();

        // Add one ack-eliciting packet
        assert!(!gen
            .update_ack(1, true, &start, QuicLevel::Application)
            .unwrap());

        // Should not need ACK immediately
        assert!(!gen.need_ack(&start, 25));

        // Should need ACK after max ack delay
        let after_delay = start + Duration::from_millis(26);
        assert!(gen.need_ack(&after_delay, 25));
    }

    #[test]
    fn test_complex_range_merging() {
        let mut gen = QuicAckGenerator::default();
        let now = Instant::now();

        // Create gaps: [10] [7-8] [4-5] [1-2]
        gen.update_ack(10, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(8, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(7, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(5, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(4, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(2, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(1, true, &now, QuicLevel::Application)
            .unwrap();

        // Fill gap: packet 9 should merge ranges
        gen.update_ack(9, true, &now, QuicLevel::Application)
            .unwrap();

        let ranges = gen.get_ranges();
        assert_eq!(ranges.len(), 2); // Should have merged [7-8] with [10]

        // Fill another gap: packet 6 should merge ranges
        gen.update_ack(6, true, &now, QuicLevel::Application)
            .unwrap();

        let ranges = gen.get_ranges();
        assert_eq!(ranges.len(), 1); // Should have merged [4-5] with [7-10]
    }

    #[test]
    fn test_handshake_level_immediate_ack() {
        let mut gen = QuicAckGenerator::default();
        let now = Instant::now();

        // Handshake packets should trigger immediate ACK
        assert!(gen.update_ack(1, true, &now, QuicLevel::Handshake).unwrap());
        assert_eq!(gen.ack_count, QUIC_ACK_MAX_COUNT);
    }

    #[test]
    fn test_max_ranges_limit() {
        // init_tracing();
        let mut gen = QuicAckGenerator::default();
        let now = Instant::now();

        // Create QUIC_MAX_RANGES + 1 separate ranges
        for i in 10..=10 + QUIC_MAX_RANGES {
            gen.update_ack((i * 3) as u64, true, &now, QuicLevel::Application)
                .unwrap();
        }

        // Next packet beyond max ranges should be added to single_ack_pns
        gen.update_ack(1, true, &now, QuicLevel::Application)
            .unwrap();
        assert!(gen.get_single_ack_pns().unwrap().contains(&1));
    }

    #[test]
    fn test_drop_ack_ranges_partial() {
        let mut gen = QuicAckGenerator::default();
        let now = Instant::now();

        // Setup ranges: [10] [7-8] [4-5] [1-2]
        gen.update_ack(10, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(8, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(7, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(5, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(4, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(2, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(1, true, &now, QuicLevel::Application)
            .unwrap();

        // Drop ranges up to 6
        gen.drop_ack_ranges(6);

        // Should keep ranges above 6
        assert_eq!(gen.get_top_range(), Some(10));
        let ranges = gen.get_ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].get_gap(), 0);
        assert_eq!(ranges[0].get_ack_range_length(), 1);
    }

    #[test]
    fn test_display_format() {
        // init_tracing();
        let mut gen = QuicAckGenerator::default();
        let now = Instant::now();

        gen.update_ack(10, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(8, true, &now, QuicLevel::Application)
            .unwrap();
        gen.update_ack(5, true, &now, QuicLevel::Application)
            .unwrap();

        let display = format!("{}", gen);
        println!("{}", display);
        assert!(display.contains("top_range Some(10)"));
        assert!(display.contains("[8, 8], [5, 5]"));
    }
}
