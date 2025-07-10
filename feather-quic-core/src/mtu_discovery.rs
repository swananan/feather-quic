// Note: Unlike TCP which has the concept of MSS (Maximum Segment Size),
// QUIC uses Maximum UDP Payload Size for MTU discovery. In this module,
// all MTU-related variables and values actually represent the maximum
// UDP payload size, not the full MTU. The actual MTU would be:
// MTU = UDP Payload Size + UDP Header(8) + IP Header(20 for IPv4, 40 for IPv6)
// For example, when we say MTU is 1500, we actually mean the UDP payload
// size is 1472 (1500 - 20 - 8) for IPv4 or 1452 (1500 - 40 - 8) for IPv6.

use std::collections::HashSet;
use tracing::{error, info, trace};

use crate::transport_parameters::MIN_UDP_PAYLOAD_SIZE;
use crate::QuicConfig;

/// Network type for MTU discovery
/// Determines protocol header sizes and available MTU probe values
#[derive(Debug, Clone, Copy)]
pub enum NetworkType {
    /// IPv4: 20-byte header + 8-byte UDP header
    IPv4,
    /// IPv6: 40-byte header + 8-byte UDP header
    IPv6,
}

/// MTU discovery state machine states
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum MtuDiscoveryState {
    /// Initial state: awaiting first probe
    Idle,
    /// Active state: probe in progress with specific MTU target
    Probing,
    /// Terminal state: discovery finished (success or max retries)
    Complete,
}

/// MTU discovery configuration parameters
#[derive(Debug, Clone)]
pub(crate) struct MtuDiscoveryConfig {
    /// Maximum allowed MTU value
    /// If None, will use the theoretical maximum based on network type
    pub(crate) max_mtu: Option<u16>,
    /// Probe packet timeout duration (ms)
    /// After this duration, probe is considered lost
    pub(crate) probe_timeout_ms: u64,
    /// Network protocol version
    /// Affects header size calculations and MTU probe values
    pub(crate) network_type: NetworkType,
    /// Maximum probe retry attempts per MTU size
    /// On reaching limit, discovery completes with last successful size
    /// Default: 3 attempts
    pub(crate) max_probe_retries: u8,

    pub(crate) first_initial_packet_size: u16,
}

impl Default for MtuDiscoveryConfig {
    fn default() -> Self {
        Self {
            max_mtu: None,
            probe_timeout_ms: 1000,
            network_type: NetworkType::IPv4,
            max_probe_retries: 3,
            first_initial_packet_size: MIN_UDP_PAYLOAD_SIZE,
        }
    }
}

impl MtuDiscoveryConfig {
    pub(crate) fn from_quic_config(config: &QuicConfig) -> Self {
        Self {
            max_mtu: None,
            first_initial_packet_size: config.get_first_initial_packet_size(),
            probe_timeout_ms: config.get_mtu_discovery_timeout(),
            network_type: config.get_mtu_discovery_network_type(),
            max_probe_retries: config.get_mtu_discovery_retry_count(),
        }
    }
}

// Ordered MTU probe values for IPv4 (ascending)
// All values represent maximum QUIC payload size: MTU - IPv4(20) - UDP(8)
const IPV4_MTU_VALUES: &[u16] = &[
    1252,  // IPv6 minimum: 1280 - 28
    1372,  // Generic tunnel: 1400 - 28
    1440,  // SLIP: 1468 - 28
    1444,  // PPPoE: 1472 - 28
    1464,  // IEEE 802.3: 1492 - 28
    1472,  // Ethernet: 1500 - 28
    4324,  // FDDI: 4352 - 28
    8972,  // Jumbo frames: 9000 - 28
    16372, // High-speed networks: 16400 - 28
    65507, // Theoretical maximum: 65535 - IPv4(20) - UDP(8)
];

// Ordered MTU probe values for IPv6 (ascending)
// All values represent maximum QUIC payload size: MTU - IPv6(40) - UDP(8)
const IPV6_MTU_VALUES: &[u16] = &[
    1232,  // IPv6 minimum: 1280 - 48
    1352,  // Generic tunnel: 1400 - 48
    1404,  // PPPoE: 1452 - 48
    1432,  // IPv6 Ethernet: 1480 - 48
    1452,  // Ethernet: 1500 - 48
    4304,  // FDDI: 4352 - 48
    8952,  // Jumbo frames: 9000 - 48
    16352, // High-speed networks: 16400 - 48
    65487, // Theoretical maximum: 65535 - IPv6(40) - UDP(8)
];

#[derive(Debug)]
pub(crate) struct MtuDiscovery {
    /// Maximum validated MTU size
    /// Updated only after successful probes
    current_mtu: u16,
    /// Current discovery phase
    state: MtuDiscoveryState,
    /// Runtime configuration
    config: MtuDiscoveryConfig,
    /// Active probe details: (target_mtu, probe_packet_numbers)
    current_probe: Option<(u16, HashSet<u64>)>,
    /// Current MTU probe sequence position
    current_probe_index: usize,
    /// Probe attempt counter
    /// - Resets on new probe or success
    /// - Increments on failure
    /// - Bounds discovery completion
    retry_count: u8,
}

impl MtuDiscovery {
    pub(crate) fn new(config: MtuDiscoveryConfig) -> Self {
        let current_mtu = config.first_initial_packet_size;
        info!("[MTU] Initial MTU: {}", current_mtu);

        Self {
            current_mtu,
            state: MtuDiscoveryState::Idle,
            config,
            current_probe: None,
            current_probe_index: 0,
            retry_count: 0,
        }
    }

    pub(crate) fn get_probe_timeout(&self) -> u64 {
        self.config.probe_timeout_ms
    }

    fn get_next_probe_mtu(&mut self) -> Option<u16> {
        let mtu_values = match self.config.network_type {
            NetworkType::IPv4 => IPV4_MTU_VALUES,
            NetworkType::IPv6 => IPV6_MTU_VALUES,
        };

        while self.current_probe_index < mtu_values.len() {
            let mtu = mtu_values[self.current_probe_index];
            self.current_probe_index += 1;

            if let Some(max_mtu) = self.config.max_mtu {
                if mtu <= max_mtu {
                    return Some(mtu);
                }
            } else {
                return Some(mtu);
            }
        }
        None
    }

    pub(crate) fn start_probe(&mut self, packet_numbers: &[u64]) -> Option<u16> {
        self.current_probe_index = 0;
        self.retry_count = 0;
        self.current_mtu = self.config.max_mtu.unwrap_or(MIN_UDP_PAYLOAD_SIZE);

        if let Some(target) = self.get_next_probe_mtu() {
            self.state = MtuDiscoveryState::Probing;
            let pns: HashSet<u64> = packet_numbers.iter().copied().collect();
            self.current_probe = Some((target, pns));
            info!("[MTU] Start probing size {}", target);
            Some(target)
        } else {
            info!("[MTU] Discovery complete, no more sizes to probe");
            self.state = MtuDiscoveryState::Complete;
            None
        }
    }

    pub(crate) fn probe_success(&mut self, pn: u64) -> Option<u16> {
        if let Some((target_mtu, _)) = &self.current_probe {
            let target_mtu = *target_mtu;
            self.current_mtu = target_mtu;
            self.current_probe = None;
            self.retry_count = 0;

            if let Some(next_target) = self.get_next_probe_mtu() {
                info!(
                    "[MTU] {} succeeded, trying next size {}",
                    target_mtu, next_target
                );
                let mut value = HashSet::new();
                value.insert(pn);
                self.current_probe = Some((next_target, value));
                Some(next_target)
            } else {
                info!(
                    "[MTU] Discovery complete, max supported size: {}",
                    target_mtu
                );
                self.state = MtuDiscoveryState::Complete;
                None
            }
        } else {
            error!("[MTU] Success check failed: no active probe");
            None
        }
    }

    pub(crate) fn probe_failed(&mut self) -> Option<u16> {
        if let Some((target_mtu, _)) = &self.current_probe {
            self.retry_count += 1;
            if self.retry_count >= self.config.max_probe_retries {
                info!(
                    "[MTU] Discovery complete: {} failed after {} attempts, using previous successful size: {}",
                    target_mtu, self.config.max_probe_retries, self.current_mtu
                );
                self.current_probe = None;
                self.state = MtuDiscoveryState::Complete;
                None
            } else {
                info!(
                    "[MTU] Size {} failed, attempt {}/{}, retrying",
                    target_mtu, self.retry_count, self.config.max_probe_retries
                );
                Some(*target_mtu)
            }
        } else {
            error!("[MTU] Failure handling failed: no active probe");
            None
        }
    }

    pub(crate) fn get_mtu(&self) -> u16 {
        self.current_mtu
    }

    pub(crate) fn has_max_mtu(&self) -> bool {
        self.config.max_mtu.is_some()
    }

    pub(crate) fn set_max_mtu(&mut self, max_mtu: u16) {
        self.config.max_mtu = Some(max_mtu);
        info!("[MTU] Set current mtu to {}", max_mtu);
    }

    #[allow(dead_code)]
    pub(crate) fn get_state(&self) -> MtuDiscoveryState {
        self.state
    }

    pub(crate) fn reset(&mut self) {
        self.state = MtuDiscoveryState::Idle;
        self.current_probe = None;
        self.current_probe_index = 0;
        self.retry_count = 0;
        trace!("[MTU] Reset to idle state");
    }

    pub(crate) fn retain_acked_probe(
        mtu_probe_pns: Option<&mut HashSet<u64>>,
        smallest: u64,
        largest: u64,
    ) {
        if let Some(pns) = mtu_probe_pns {
            trace!("MTU check pns {:?}, range [{}, {}]", pns, smallest, largest);
            if pns.iter().any(|pn| *pn >= smallest && *pn <= largest) {
                info!(
                    "MTU find acked pns {:?}, range [{}, {}]",
                    pns, smallest, largest
                );
                // Clear the packet numbers since these MTU probe packets have been acknowledged,
                // indicating successful MTU discovery for this probe size
                pns.clear();
            }
        }
    }

    pub(crate) fn get_mtu_probe_pns(&self) -> Option<HashSet<u64>> {
        if self.state != MtuDiscoveryState::Probing {
            return None;
        }
        self.current_probe.as_ref().map(|(_, pns)| pns.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtu_discovery_sequence() {
        let mut discovery = MtuDiscovery::new(MtuDiscoveryConfig::default());
        let packet_numbers = vec![1, 2, 3];

        // Start probing
        let first_target = discovery.start_probe(&packet_numbers);
        assert!(first_target.is_some());
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Probing);

        // Simulate successful probe
        let next_target = discovery.probe_success(packet_numbers[0]);
        assert!(next_target.is_some());
        assert!(discovery.get_mtu() >= MIN_UDP_PAYLOAD_SIZE);

        // Continue until complete
        let mut probe_count = 0;
        while let Some(target) = discovery.probe_success(packet_numbers[0]) {
            probe_count += 1;
            assert_eq!(discovery.get_state(), MtuDiscoveryState::Probing);
            assert!(target >= MIN_UDP_PAYLOAD_SIZE);
            // Verify target is within IPv4 MTU values
            assert!(IPV4_MTU_VALUES.contains(&target));
        }

        assert_eq!(discovery.get_state(), MtuDiscoveryState::Complete);
        assert!(probe_count > 0);
    }

    #[test]
    fn test_mtu_discovery_with_max_mtu() {
        let config = MtuDiscoveryConfig {
            max_mtu: Some(1500),
            network_type: NetworkType::IPv4,
            ..Default::default()
        };
        let mut discovery = MtuDiscovery::new(config);
        let packet_numbers = vec![1, 2, 3];

        // Start probing
        let first_target = discovery.start_probe(&packet_numbers);
        assert!(first_target.is_some());
        assert!(first_target.unwrap() <= 1500);

        // Verify all subsequent probes respect max_mtu
        while let Some(target) = discovery.probe_success(packet_numbers[0]) {
            assert!(target <= 1500);
        }
    }

    #[test]
    fn test_mtu_discovery_ipv6() {
        let config = MtuDiscoveryConfig {
            network_type: NetworkType::IPv6,
            ..Default::default()
        };
        let mut discovery = MtuDiscovery::new(config.clone());
        let packet_numbers = vec![1, 2, 3];

        // Start probing
        let first_target = discovery.start_probe(&packet_numbers);
        assert!(first_target.is_some());

        // Verify initial MTU matches config minimum
        assert_eq!(discovery.get_mtu(), MIN_UDP_PAYLOAD_SIZE);

        // Verify target is within IPv6 MTU values
        assert!(IPV6_MTU_VALUES.contains(&first_target.unwrap()));
    }

    #[test]
    fn test_mtu_probe_packet_tracking() {
        let mut discovery = MtuDiscovery::new(MtuDiscoveryConfig::default());
        let packet_numbers = vec![1, 2, 3, 4, 5];

        // Start probe and verify packet numbers are tracked
        discovery.start_probe(&packet_numbers);
        let probe_pns = discovery.get_mtu_probe_pns();
        assert!(probe_pns.is_some());
        assert_eq!(probe_pns.unwrap().len(), packet_numbers.len());

        // Verify packet tracking in non-probing state
        discovery.state = MtuDiscoveryState::Complete;
        assert!(discovery.get_mtu_probe_pns().is_none());
    }

    #[test]
    fn test_mtu_discovery_state_transitions() {
        let mut discovery = MtuDiscovery::new(MtuDiscoveryConfig::default());

        // Initial state should be Idle
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Idle);

        // Start probing should transition to Probing state
        let packet_numbers = vec![1, 2, 3];
        discovery.start_probe(&packet_numbers);
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Probing);

        // Reset should return to Idle state
        discovery.reset();
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Idle);

        // After reset, should be able to start probing again
        let target = discovery.start_probe(&packet_numbers);
        assert!(target.is_some());
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Probing);

        // Multiple failures should lead to Complete state
        for _ in 0..discovery.config.max_probe_retries {
            discovery.probe_failed();
        }
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Complete);

        // Reset should work from Complete state too
        discovery.reset();
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Idle);
    }

    #[test]
    fn test_retain_acked_probe() {
        let mut discovery = MtuDiscovery::new(MtuDiscoveryConfig::default());
        let packet_numbers = vec![1, 2, 3, 4, 5];

        // Start probing to initialize packet tracking
        discovery.start_probe(&packet_numbers);

        // Get mutable reference to probe packet numbers
        let mut probe_pns = discovery.get_mtu_probe_pns().unwrap();
        assert_eq!(probe_pns.len(), packet_numbers.len());

        // Test when acked range doesn't contain any probe packets
        MtuDiscovery::retain_acked_probe(Some(&mut probe_pns), 10, 15);
        assert_eq!(
            probe_pns.len(),
            packet_numbers.len(),
            "Should not clear PNs when no acks match"
        );

        // Test when acked range contains a probe packet
        MtuDiscovery::retain_acked_probe(Some(&mut probe_pns), 1, 3);
        assert_eq!(probe_pns.len(), 0, "Should clear PNs when acks match");

        // Test with None input (should not panic)
        MtuDiscovery::retain_acked_probe(None, 1, 3);
    }

    #[test]
    fn test_reset_clears_state() {
        let mut discovery = MtuDiscovery::new(MtuDiscoveryConfig::default());
        let packet_numbers = vec![1, 2, 3];

        // Setup some state
        let target = discovery.start_probe(&packet_numbers);
        assert!(target.is_some());
        assert!(discovery.get_mtu_probe_pns().is_some());

        // Reset should clear everything
        discovery.reset();
        assert_eq!(discovery.get_state(), MtuDiscoveryState::Idle);
        assert!(discovery.get_mtu_probe_pns().is_none());
        assert_eq!(discovery.current_probe_index, 0);
        assert_eq!(discovery.retry_count, 0);

        // Should be able to start fresh after reset
        let new_target = discovery.start_probe(&packet_numbers);
        assert!(new_target.is_some());
        assert_eq!(new_target, target, "Reset should not affect MTU sequence");
    }
}
