use anyhow::Result;
use std::time::Duration;
use tracing::{trace, warn};

use crate::connection::QuicLevel;

const QUIC_DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
const QUIC_INITIAL_RTT: u16 = 333; // Unit is milliseconds

// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2-6
const QUIC_KTIME_THRESHOLD: f32 = 9.0 / 8.0;
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.2-2.6.1
const QUIC_KGRANULARITY: Duration = Duration::from_millis(1);

#[derive(Debug)]
pub(crate) struct QuicRttGenerator {
    latest: Duration,

    // The minimum value over a period of time (min_rtt)
    min_rtt: Option<Duration>,

    // An exponentially weighted moving average
    smoothed_rtt: Option<Duration>,

    // The mean deviation
    variation: Duration,

    pub(crate) time_threshold: Option<f32>,

    // From the peer side
    pub(crate) max_ack_delay: Option<u16>,
    pub(crate) ack_delay_exponent: Option<u8>,
}

impl Default for QuicRttGenerator {
    fn default() -> Self {
        Self {
            smoothed_rtt: None,
            min_rtt: None,
            variation: Duration::from_millis(QUIC_INITIAL_RTT as u64 / 2),
            ack_delay_exponent: None,
            max_ack_delay: None,
            latest: Duration::from_millis(QUIC_INITIAL_RTT as u64),
            time_threshold: None,
        }
    }
}

impl QuicRttGenerator {
    pub(crate) fn get_rtt(&self) -> Duration {
        let rtt = self.smoothed_rtt.unwrap_or(self.latest);
        trace!(
            "Get RTT: {:?} (smoothed: {:?}, latest: {:?})",
            rtt,
            self.smoothed_rtt,
            self.latest
        );
        rtt
    }

    pub(crate) fn get_pto(&self, level: QuicLevel) -> Duration {
        // When the PTO is armed for Initial or Handshake packet number spaces,
        // the max_ack_delay in the PTO period computation is set to 0,
        // since the peer is expected to not delay these packets intentionally;
        let max_ack_delay = if level == QuicLevel::Application {
            // TODO: confirm if it should be 25ms by defalut? if we don't recevied the max_ack_delay
            // transport parameter from the peer side
            let delay = self.max_ack_delay.unwrap_or(0);
            trace!("Using application level max_ack_delay: {}", delay);
            delay
        } else {
            trace!("Using zero max_ack_delay for {:?} level", level);
            0
        };

        let rtt = self.get_rtt();
        let variation = self.variation.max(QUIC_KGRANULARITY);
        let pto = rtt + 4 * variation + Duration::from_millis(max_ack_delay as u64);

        trace!(
            "Calculated PTO: {:?} (RTT: {:?}, variation: {:?}, max_ack_delay: {}ms)",
            pto,
            rtt,
            variation,
            max_ack_delay
        );
        pto
    }

    pub(crate) fn get_time_threhold(&self) -> Duration {
        let base_rtt = self.get_rtt().max(self.latest);
        let threshold = self.time_threshold.unwrap_or(QUIC_KTIME_THRESHOLD);
        let result = base_rtt.mul_f32(threshold).max(QUIC_KGRANULARITY);

        trace!(
            "Calculated time threshold: {:?} (base RTT: {:?}, threshold factor: {})",
            result,
            base_rtt,
            threshold
        );
        result
    }

    pub(crate) fn update(
        &mut self,
        level: QuicLevel,
        delay: u64,
        latest_rtt: Duration,
    ) -> Result<()> {
        trace!(
            "Enter RTT update - level: {:?}, ack_delay: {}, latest_rtt: {:?}, current state: {:?}",
            level,
            delay,
            latest_rtt,
            self
        );
        let mut ack_delay = if matches!(level, QuicLevel::Application) {
            delay
                << self
                    .ack_delay_exponent
                    .unwrap_or(QUIC_DEFAULT_ACK_DELAY_EXPONENT)
        } else {
            0
        };
        if let Some(max_ack_delay) = self.max_ack_delay {
            // https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3-7.2
            if level == QuicLevel::Application && (max_ack_delay as u64 * 1000) < ack_delay {
                warn!("Ack delay {}ns from the ack frame shouldn't be larger then peer side transport parameter max_ack_delay {}",
                    ack_delay, max_ack_delay);
                ack_delay = max_ack_delay as u64;
            }
        }

        // Unit is microseconds
        let ack_delay = Duration::from_micros(ack_delay);

        self.latest = latest_rtt;
        let min_rtt = self.min_rtt.map_or(latest_rtt, |m| m.min(latest_rtt));
        self.min_rtt = Some(min_rtt);

        if let Some(smoothed) = self.smoothed_rtt {
            let adjusted_rtt = if min_rtt + ack_delay <= self.latest {
                trace!(
                    "Adjusting RTT with ack_delay: latest({:?}) - delay({:?})",
                    self.latest,
                    ack_delay
                );
                self.latest - ack_delay
            } else {
                trace!("Using unadjusted RTT: {:?}", self.latest);
                self.latest
            };

            let var_sample = smoothed.abs_diff(adjusted_rtt);
            self.variation = (3 * self.variation + var_sample) / 4;
            self.smoothed_rtt = Some((7 * smoothed + adjusted_rtt) / 8);

            trace!(
                "RTT metrics updated: adjusted_rtt={:?}, state: {:?}",
                adjusted_rtt,
                self
            );
        } else {
            self.smoothed_rtt = Some(self.latest);
            self.variation = self.latest / 2;
            self.min_rtt = Some(self.latest);

            trace!("RTT metrics initialized: {:?}", self);
        }

        trace!("RTT update complete: {:?}", self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rtt_generator() {
        let generator = QuicRttGenerator::default();

        assert_eq!(
            generator.latest,
            Duration::from_millis(QUIC_INITIAL_RTT as u64)
        );
        assert_eq!(
            generator.variation,
            Duration::from_millis(QUIC_INITIAL_RTT as u64 / 2)
        );
        assert_eq!(generator.smoothed_rtt, None);
        assert_eq!(generator.min_rtt, None);
        assert_eq!(generator.ack_delay_exponent, None);
        assert_eq!(generator.max_ack_delay, None);
        assert_eq!(generator.time_threshold, None);
    }

    #[test]
    fn test_get_rtt() {
        let mut generator = QuicRttGenerator::default();

        // When smoothed_rtt is None, should return latest
        assert_eq!(
            generator.get_rtt(),
            Duration::from_millis(QUIC_INITIAL_RTT as u64)
        );

        // Update RTT and check again
        generator
            .update(QuicLevel::Initial, 0, Duration::from_millis(100))
            .unwrap();
        assert_eq!(generator.get_rtt(), Duration::from_millis(100));
    }

    #[test]
    fn test_get_pto() {
        let mut generator = QuicRttGenerator::default();

        // Test Initial level (should use 0 max_ack_delay)
        let pto_initial = generator.get_pto(QuicLevel::Initial);
        assert!(pto_initial > generator.get_rtt());

        // Test Application level with max_ack_delay
        generator.max_ack_delay = Some(25);
        let pto_app = generator.get_pto(QuicLevel::Application);
        assert!(pto_app > pto_initial); // Should be larger due to max_ack_delay
    }

    #[test]
    fn test_rtt_update() {
        let mut generator = QuicRttGenerator::default();

        // First update should initialize smoothed_rtt
        generator
            .update(QuicLevel::Initial, 0, Duration::from_millis(100))
            .unwrap();
        assert_eq!(generator.latest, Duration::from_millis(100));
        assert_eq!(generator.smoothed_rtt, Some(Duration::from_millis(100)));
        assert_eq!(generator.min_rtt, Some(Duration::from_millis(100)));

        // Subsequent update should adjust smoothed_rtt
        generator
            .update(QuicLevel::Initial, 0, Duration::from_millis(200))
            .unwrap();
        assert_eq!(generator.latest, Duration::from_millis(200));
        assert!(generator.smoothed_rtt.unwrap() > Duration::from_millis(100));
        assert_eq!(generator.min_rtt, Some(Duration::from_millis(100))); // min_rtt should remain unchanged
    }

    #[test]
    fn test_ack_delay_handling() {
        let mut generator = QuicRttGenerator {
            ack_delay_exponent: Some(3),
            max_ack_delay: Some(25),
            ..Default::default()
        };

        // Update with ack_delay in Application level
        generator
            .update(QuicLevel::Application, 2, Duration::from_millis(100))
            .unwrap();

        // ack_delay should be applied (2 << 3 = 16 microseconds)
        assert_eq!(generator.latest, Duration::from_millis(100));

        // Test with ack_delay exceeding max_ack_delay
        generator
            .update(QuicLevel::Application, 1000, Duration::from_millis(150))
            .unwrap();
        // Should be capped at max_ack_delay
        assert_eq!(generator.latest, Duration::from_millis(150));
    }

    #[test]
    fn test_get_time_threshold() {
        let mut generator = QuicRttGenerator::default();

        // Test with default threshold
        let threshold = generator.get_time_threhold();
        assert!(threshold >= QUIC_KGRANULARITY);

        // Test with custom threshold
        generator.time_threshold = Some(2.0);
        let custom_threshold = generator.get_time_threhold();
        assert!(custom_threshold > threshold);
    }
}
