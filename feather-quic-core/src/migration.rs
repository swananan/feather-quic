use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use tracing::{error, info, trace, warn};

/// QUIC Path state machine for connection migration
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum QuicPathState {
    /// Path is unvalidated, cannot be used for sending data
    Unvalidated,
    /// Path validation is in progress
    Validating {
        /// Path challenge data sent
        challenge_data: [u8; 8],
        /// When the path challenge was sent
        challenge_sent_time: Instant,
        /// Number of validation attempts
        validation_attempts: u8,
    },
    /// Path is validated and can be used for sending data
    Validated,
    /// Path validation failed
    Failed,
    /// Path was retired
    Retired,
}

const MAX_VALIDATION_ATTEMPTS: u8 = 2;
const MAX_VALIDATION_TIMEOUT_MS: u64 = 600;

/// Migration result for migration_switch_result callback
#[derive(Debug, Clone)]
pub enum MigrationResult {
    /// Migration failed
    MigrationFailed(String),
    /// Migration succeeded
    MigrationSuccess,
    /// Migration to preferred address succeeded
    MigrationPreferredAddressSuccess,
}

/// Represents a QUIC path with associated connection ID and validation state
#[derive(Debug, Clone)]
pub(crate) struct QuicPath {
    /// Path ID for internal tracking
    pub(crate) path_id: u64,
    /// Destination Connection ID (dcid) to use for this path
    pub(crate) connection_id: Option<Vec<u8>>,
    /// Connection ID sequence number associated with this path
    pub(crate) connection_id_sequence: Option<u64>,
    /// Target address for this path
    pub(crate) target_address: SocketAddr,
    /// Current state of path validation
    pub(crate) state: QuicPathState,
    /// When this path was created
    pub(crate) created_time: Instant,
    /// When this path was last used for sending data
    pub(crate) last_used_time: Option<Instant>,
}

impl QuicPath {
    /// Create a new unvalidated QUIC path
    pub(crate) fn new(
        path_id: u64,
        connection_id: Option<Vec<u8>>,
        target_address: SocketAddr,
        current_time: std::time::Instant,
    ) -> Self {
        Self {
            path_id,
            connection_id,
            connection_id_sequence: None,
            target_address,
            state: QuicPathState::Unvalidated,
            created_time: current_time,
            last_used_time: None,
        }
    }

    /// Check if this path is available for sending data
    pub(crate) fn is_available(&self) -> bool {
        matches!(self.state, QuicPathState::Validated)
    }

    /// Check if this path is being validated
    pub(crate) fn is_validating(&self) -> bool {
        matches!(self.state, QuicPathState::Validating { .. })
    }

    /// Start path validation
    pub(crate) fn start_validation(
        &mut self,
        challenge_data: [u8; 8],
        current_time: std::time::Instant,
    ) {
        trace!(
            "Started path validation for path {}: {:?}, challenge_data {:x?}",
            self.path_id,
            self.target_address,
            &challenge_data
        );

        self.state = QuicPathState::Validating {
            challenge_data,
            challenge_sent_time: current_time,
            validation_attempts: 1,
        };
    }

    /// Complete path validation successfully
    pub(crate) fn complete_validation(&mut self) -> Result<()> {
        if let QuicPathState::Validating {
            challenge_sent_time,
            ..
        } = self.state
        {
            let validation_rtt = challenge_sent_time.elapsed();
            self.state = QuicPathState::Validated;
            info!(
                "Path validation completed for path {}: {:?}, RTT: {:?}",
                self.path_id, self.target_address, validation_rtt
            );
            Ok(())
        } else {
            warn!(
                "Attempted to complete validation on non-validating path: {}",
                self.path_id
            );
            Ok(())
        }
    }

    pub(crate) fn succeed_validation(&mut self) {
        self.state = QuicPathState::Validated;
        info!(
            "Path validation succeed for path id {}: {:?}, cid seq {:?}",
            self.path_id, self.target_address, self.connection_id_sequence
        );
    }

    pub(crate) fn retire(&mut self) {
        self.state = QuicPathState::Retired;
        warn!(
            "Path validation retired for path {}: {:?}",
            self.path_id, self.target_address
        );
    }

    pub(crate) fn fail_validation(&mut self) {
        self.state = QuicPathState::Failed;
        warn!(
            "Path validation failed for path {}: {:?}",
            self.path_id, self.target_address
        );
    }

    pub(crate) fn get_challenge_data(&self) -> Option<[u8; 8]> {
        if let QuicPathState::Validating { challenge_data, .. } = self.state {
            Some(challenge_data)
        } else {
            None
        }
    }
}

/// Manages multiple QUIC paths for connection migration
#[derive(Debug)]
pub(crate) struct QuicMigration {
    /// All available paths indexed by path ID
    pub(crate) paths: HashMap<u64, QuicPath>,
    /// Currently active path ID
    pub(crate) active_path_id: u64,
    /// Next path ID to assign
    pub(crate) next_path_id: u64,
    /// Path validation timeout
    pub(crate) path_validation_timeout: std::time::Duration,
    /// Maximum number of paths to maintain
    pub(crate) max_paths: usize,

    /// Available peer connection IDs waiting to be assigned to paths
    /// sequence_number -> (connection_id, stateless_reset_token)
    pub(crate) available_peer_connection_ids: HashMap<u64, (Vec<u8>, [u8; 16])>,
    /// Maximum retire_prior_to value from peer
    pub(crate) max_peer_retire_prior_to: u64,

    /// Pending migration callback result
    pub(crate) migration_result_pending: Option<(u64, u64, MigrationResult)>,
}

impl QuicMigration {
    /// Create a new migration manager with initial path
    pub(crate) fn new(max_paths: usize) -> Self {
        Self {
            paths: HashMap::new(),
            active_path_id: 0,
            next_path_id: 0,
            path_validation_timeout: std::time::Duration::from_millis(MAX_VALIDATION_TIMEOUT_MS),
            max_paths,
            available_peer_connection_ids: HashMap::new(),
            max_peer_retire_prior_to: 0,
            migration_result_pending: None,
        }
    }

    /// Add a new path for validation with automatic CID assignment
    pub(crate) fn add_path(
        &mut self,
        target_address: SocketAddr,
        current_time: std::time::Instant,
    ) -> Result<u64> {
        if self.paths.len() >= self.max_paths {
            // Remove oldest failed or unvalidated path
            self.cleanup_old_paths(current_time);
        }

        let path_id = self.next_path_id;
        self.next_path_id += 1;

        // Try to get an available connection ID for this path
        let (connection_id, sequence) = if let Some((seq, cid)) =
            self.get_available_peer_connection_id(self.get_active_connection_id_sequence())
        {
            info!("Found available CID for path {}: {:x?}", path_id, cid);
            (Some(cid), seq)
        } else {
            // Only happens when the first path is created
            info!("No available CID, creating path without CID");
            (None, 0)
        };

        if connection_id.is_some() {
            info!(
                "Added new path {} with auto-assigned CID (seq={}): {:?}",
                path_id, sequence, target_address
            );
        } else {
            info!(
                "Added new path {} without CID (will be assigned later): {:?}, \
                connection_id_sequence {}",
                path_id, target_address, sequence,
            );
        }

        let mut path = QuicPath::new(path_id, connection_id, target_address, current_time);
        path.connection_id_sequence = Some(sequence);

        self.paths.insert(path_id, path);

        Ok(path_id)
    }

    /// Add a new path with a specific connection ID (for handshake and preferred address)
    pub(crate) fn add_path_with_connection_id(
        &mut self,
        connection_id: Vec<u8>,
        target_address: SocketAddr,
        sequence: u64,
        current_time: std::time::Instant,
    ) -> Result<u64> {
        if self.paths.len() >= self.max_paths {
            // Remove oldest failed or unvalidated path
            self.cleanup_old_paths(current_time);
        }

        let path_id = self.next_path_id;
        self.next_path_id += 1;

        let mut path = QuicPath::new(
            path_id,
            Some(connection_id.clone()),
            target_address,
            current_time,
        );
        path.connection_id_sequence = Some(sequence);

        self.paths.insert(path_id, path);

        info!(
            "Added new path {} with specific CID (seq={}): {:?}",
            path_id, sequence, target_address
        );

        Ok(path_id)
    }

    /// Get the currently active path
    pub(crate) fn get_active_path(&self) -> Option<&QuicPath> {
        self.paths.get(&self.active_path_id)
    }

    /// Get the currently active path mutably
    pub(crate) fn get_active_path_mut(&mut self) -> Option<&mut QuicPath> {
        self.paths.get_mut(&self.active_path_id)
    }

    /// Get a path by ID
    pub(crate) fn get_path(&self, path_id: u64) -> Option<&QuicPath> {
        self.paths.get(&path_id)
    }

    /// Get a path by ID mutably
    pub(crate) fn get_path_mut(&mut self, path_id: u64) -> Option<&mut QuicPath> {
        self.paths.get_mut(&path_id)
    }

    pub(crate) fn set_active_path_validated(&mut self) {
        if let Some(p) = self.paths.get_mut(&self.active_path_id) {
            p.succeed_validation();
        }
    }

    pub(crate) fn set_path_retired(&mut self, path_id: u64) {
        if let Some(p) = self.paths.get_mut(&path_id) {
            p.retire();
        }
    }

    /// Switch to a different path if it's validated
    /// Returns the old active path ID if switching was successful
    pub(crate) fn switch_to_path(&mut self, path_id: u64, validated_check: bool) -> Result<u64> {
        if let Some(path) = self.paths.get(&path_id) {
            if path.is_available() || !validated_check {
                let old_path_id = self.active_path_id;
                self.active_path_id = path_id;
                info!(
                    "Switched active path from {} to {}: {:?}",
                    old_path_id, path_id, path.target_address
                );
                Ok(old_path_id)
            } else {
                Err(anyhow!("Cannot switch to path {} - not validated", path_id))
            }
        } else {
            Err(anyhow!("Cannot find the path {} - not existed", path_id))
        }
    }

    /// Check for timed out path validations and return path ids that need retry
    pub(crate) fn check_validation_timeouts(
        &mut self,
        current_time: std::time::Instant,
    ) -> Vec<u64> {
        let timeout = self.path_validation_timeout;
        let mut paths_to_retry = Vec::new();
        let mut paths_to_fail = Vec::new();

        for (path_id, path) in &self.paths {
            match &path.state {
                QuicPathState::Validating {
                    challenge_sent_time,
                    validation_attempts,
                    ..
                } => {
                    let elapsed = current_time.duration_since(*challenge_sent_time);
                    if elapsed > timeout {
                        if *validation_attempts < MAX_VALIDATION_ATTEMPTS {
                            warn!("[Migration] Path {} validation timed out ({} ms elapsed, attempt {}), \
                                will retry", path_id, elapsed.as_millis(), validation_attempts);
                            paths_to_retry.push(*path_id);
                        } else {
                            warn!("[Migration] Path {} validation timed out ({} ms elapsed, attempt {}), \
                                will fail", path_id, elapsed.as_millis(), validation_attempts);
                            paths_to_fail.push(*path_id);
                        }
                    } else {
                        trace!(
                            "[Migration] Path {} validating, {} ms elapsed, attempt {}",
                            path_id,
                            elapsed.as_millis(),
                            validation_attempts
                        );
                    }
                }
                QuicPathState::Unvalidated => {
                    trace!("[Migration] Path {} is unvalidated", path_id);
                }
                QuicPathState::Validated => {
                    trace!("[Migration] Path {} is validated", path_id);
                }
                QuicPathState::Failed => {
                    trace!("[Migration] Path {} is failed", path_id);
                }
                QuicPathState::Retired => {
                    trace!("[Migration] Path {} is retired", path_id);
                }
            }
        }

        for path_id in &paths_to_retry {
            if let Some(path) = self.paths.get_mut(path_id) {
                if let QuicPathState::Validating {
                    validation_attempts,
                    ..
                } = &mut path.state
                {
                    *validation_attempts += 1;
                }
            }
        }

        for path_id in paths_to_fail {
            if let Some(path) = self.paths.get_mut(&path_id) {
                path.fail_validation();
                // Set migration failure callback if this was a migration attempt
                let old_path_id = self.active_path_id;
                let new_path_id = path_id;
                self.set_migration_result_pending(
                    old_path_id,
                    new_path_id,
                    MigrationResult::MigrationFailed("Path validation timeout".to_string()),
                );
            }
        }

        paths_to_retry
    }

    fn cleanup_old_paths(&mut self, current_time: std::time::Instant) {
        let cleanup_threshold = std::time::Duration::from_secs(60);

        let mut paths_to_remove = Vec::new();

        for (path_id, path) in &self.paths {
            if *path_id == self.active_path_id {
                continue; // Never remove active path
            }

            let should_remove = match path.state {
                QuicPathState::Failed => true,
                QuicPathState::Retired => true,
                QuicPathState::Unvalidated => {
                    current_time.duration_since(path.created_time) > cleanup_threshold
                }
                QuicPathState::Validating { .. } => false, // Let validation timeout handle these
                QuicPathState::Validated => {
                    // Remove validated but unused paths after a long time
                    if let Some(last_used) = path.last_used_time {
                        current_time.duration_since(last_used) > cleanup_threshold * 2
                    } else {
                        current_time.duration_since(path.created_time) > cleanup_threshold * 2
                    }
                }
            };

            if should_remove {
                paths_to_remove.push(*path_id);
            }
        }

        for path_id in paths_to_remove {
            self.paths.remove(&path_id);
            info!("Removed old path: {}", path_id);
        }
    }

    /// Get the current target address for sending data
    pub(crate) fn get_current_target_address(&self) -> Option<SocketAddr> {
        self.get_active_path().map(|p| p.target_address)
    }

    /// Get the current connection ID for sending data  
    pub(crate) fn get_current_connection_id(&self) -> Option<&[u8]> {
        self.get_active_path()
            .and_then(|p| p.connection_id.as_deref())
    }

    /// Set the current connection ID (dcid) for the active path
    pub(crate) fn set_current_connection_id(&mut self, dcid: Vec<u8>) -> Result<()> {
        if let Some(active_path) = self.get_active_path_mut() {
            info!(
                "Updated active path {} dcid: {:x?} -> {:x?}",
                active_path.path_id, active_path.connection_id, dcid
            );
            active_path.connection_id = Some(dcid);
            Ok(())
        } else {
            error!("No active path available to set connection ID");
            Err(anyhow::anyhow!("No active path available"))
        }
    }

    /// Get the current connection ID (dcid) for the active path
    pub(crate) fn get_current_dcid(&self) -> Option<Vec<u8>> {
        self.get_active_path().and_then(|p| p.connection_id.clone())
    }

    /// Get the connection ID sequence number for a specific path
    pub(crate) fn get_path_connection_id_sequence(&self, path_id: u64) -> Option<u64> {
        self.get_path(path_id)
            .and_then(|path| path.connection_id_sequence)
    }

    pub(crate) fn handle_path_response(&mut self, response_data: [u8; 8]) -> Result<Option<u64>> {
        for (path_id, path) in &mut self.paths {
            if let Some(challenge_data) = path.get_challenge_data() {
                if challenge_data == response_data {
                    path.complete_validation()?;
                    info!("Path {} validation completed successfully", path_id);
                    return Ok(Some(*path_id));
                }
            }
        }

        warn!(
            "Received PATH_RESPONSE with unknown challenge data: {:?}",
            response_data
        );
        Ok(None)
    }

    /// Add a peer connection ID to the available pool
    pub(crate) fn add_peer_connection_id(
        &mut self,
        sequence_number: u64,
        connection_id: Vec<u8>,
        reset_token: [u8; 16],
    ) -> Result<()> {
        // Check if this sequence number already exists
        if self
            .available_peer_connection_ids
            .contains_key(&sequence_number)
        {
            info!(
                "Peer connection ID sequence {} already exists, ignoring duplicate",
                sequence_number
            );
            return Ok(());
        }

        let cid_clone = connection_id.clone();
        self.available_peer_connection_ids
            .insert(sequence_number, (connection_id, reset_token));

        info!(
            "Added peer connection ID: sequence={}, cid={:x?}",
            sequence_number, cid_clone
        );

        Ok(())
    }

    /// Get an available peer connection ID for migration
    /// Returns (sequence_number, connection_id) if available
    pub(crate) fn get_available_peer_connection_id(
        &self,
        exclude_sequence: u64,
    ) -> Option<(u64, Vec<u8>)> {
        self.available_peer_connection_ids
            .iter()
            .find(|(&seq, _)| seq != exclude_sequence && seq >= self.max_peer_retire_prior_to)
            .map(|(&seq, (cid, _))| (seq, cid.clone()))
    }

    /// Update the maximum retire_prior_to value from peer
    pub(crate) fn update_max_peer_retire_prior_to(&mut self, retire_prior_to: u64) {
        if retire_prior_to > self.max_peer_retire_prior_to {
            self.max_peer_retire_prior_to = retire_prior_to;
            info!("Updated max_peer_retire_prior_to to {}", retire_prior_to);
        }
    }

    /// Retire peer connection IDs with sequence number < retire_prior_to
    pub(crate) fn retire_peer_connection_ids_before(&mut self, retire_prior_to: u64) {
        let sequences_to_retire: Vec<u64> = self
            .available_peer_connection_ids
            .keys()
            .filter(|&&seq| seq < retire_prior_to)
            .copied()
            .collect();

        for seq in sequences_to_retire {
            if let Some((retired_cid, _)) = self.available_peer_connection_ids.remove(&seq) {
                info!(
                    "Retired peer connection ID: sequence={}, cid={:x?}",
                    seq, retired_cid
                );
            }
        }
    }

    /// Get the current connection ID sequence number from the active path
    pub(crate) fn get_active_connection_id_sequence(&self) -> u64 {
        self.get_active_path()
            .and_then(|path| path.connection_id_sequence)
            .unwrap_or(0)
    }

    /// Check if a peer connection ID sequence number has been retired
    pub(crate) fn is_peer_connection_id_retired(&self, sequence_number: u64) -> bool {
        sequence_number < self.max_peer_retire_prior_to
    }

    /// Get the number of available peer connection IDs
    pub(crate) fn get_available_peer_connection_id_count(&self) -> usize {
        self.available_peer_connection_ids.len()
    }

    /// Get all available peer connection IDs
    pub(crate) fn get_all_peer_connection_ids(&self) -> &HashMap<u64, (Vec<u8>, [u8; 16])> {
        &self.available_peer_connection_ids
    }

    /// Set the active path id
    pub(crate) fn set_active_path_id(&mut self, path_id: u64) {
        self.active_path_id = path_id;
    }

    pub(crate) fn set_migration_result_pending(
        &mut self,
        old_path_id: u64,
        new_path_id: u64,
        result: MigrationResult,
    ) {
        self.migration_result_pending = Some((old_path_id, new_path_id, result));
    }

    pub(crate) fn has_validating_path(&self) -> bool {
        self.paths.values().any(|p| p.is_validating())
    }
}
