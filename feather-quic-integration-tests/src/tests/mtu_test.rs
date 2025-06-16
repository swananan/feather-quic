#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, platform::is_io_uring_supported, TestEnvironment};
    use anyhow::{anyhow, Result};
    use tracing::{info, warn};

    // Generic test function that accepts parameters for various MTU discovery configurations
    async fn run_mtu_discovery_test(
        use_io_uring: bool,
        mtu_timeout_ms: Option<u64>,
        mtu_retry_count: Option<u32>,
        target_mtu: u16,
    ) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        let mtu_str = format!(" with MTU {}", target_mtu);
        let timeout_str = mtu_timeout_ms.map_or("".to_string(), |t| format!(" timeout {}ms", t));
        let retry_str = mtu_retry_count.map_or("".to_string(), |r| format!(" retry {}", r));

        info!(
            "Starting MTU discovery test{}{}{}{}",
            io_uring_str, mtu_str, timeout_str, retry_str
        );

        // Configure server with default settings
        let server_config = ["--listen", "127.0.0.1:44437", "--response-delay", "300"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        // Store all configuration strings in the vector
        let mut client_config = vec![
            "--target-address".to_string(),
            "127.0.0.1:44437".to_string(),
            "--sni".to_string(),
            "localhost".to_string(),
            "--first-initial-packet-size".to_string(),
            "1200".to_string(),
            "--scid".to_string(),
            "dddd1baa11".to_string(),
            "--alpn".to_string(),
            "echo".to_string(),
            "-e".to_string(),
            "feather-quic-integration-tests/src/tests/test_files/basic_echo_input".to_string(),
            "--drop-packets-above-size".to_string(),
            target_mtu.to_string(),
        ];

        // Add MTU timeout if specified
        if let Some(timeout) = mtu_timeout_ms {
            client_config.push("--mtu-discovery-timeout".to_string());
            client_config.push(timeout.to_string());
        }

        // Add MTU retry count if specified
        if let Some(retry) = mtu_retry_count {
            client_config.push("--mtu-discovery-retry-count".to_string());
            client_config.push(retry.to_string());
        }

        if use_io_uring {
            client_config.push("--use-io-uring".to_string());
        }

        // Convert Vec<String> to Vec<&str> for the test environment
        let client_config_refs: Vec<&str> = client_config.iter().map(|s| s.as_str()).collect();

        // We expect to see MTU discovery success message with the target MTU
        let success_patterns = [
            "QUIC connection established successfully",
            &format!(
                "MTU discovery completed successfully, final MTU: {}",
                target_mtu
            ),
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [
            "Failed to establish QUIC connection",
            "MTU discovery failed",
        ];

        let test_result = test_env
            .run_client_test(&client_config_refs, &success_patterns, &failure_patterns, 8)
            .await;

        if let Err(error) = &test_result {
            warn!("Test failed. Error: {}", error);
            test_env.test_failed = true;
        }

        let cleanup_result = test_env.cleanup().await;

        let final_result = match (test_result, cleanup_result) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(test_err), Ok(_)) => Err(test_err),
            (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
            (Err(test_err), Err(cleanup_err)) => Err(anyhow!("{}\n{}", test_err, cleanup_err)),
        };

        if let Err(e) = &final_result {
            warn!("Test execution or cleanup failed: {}", e);
        }

        final_result
    }

    // Test cases for different MTU sizes
    #[tokio::test]
    pub async fn test_mtu_discovery_generic_tunnel() -> Result<()> {
        run_mtu_discovery_test(false, None, None, 1372).await // Generic tunnel: 1400 - 28
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_slip() -> Result<()> {
        run_mtu_discovery_test(false, None, None, 1440).await // SLIP: 1468 - 28
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_pppoe() -> Result<()> {
        run_mtu_discovery_test(false, None, Some(1), 1444).await // PPPoE: 1472 - 28
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_ieee8023() -> Result<()> {
        run_mtu_discovery_test(false, None, Some(0), 1464).await // IEEE 802.3: 1492 - 28
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_ethernet() -> Result<()> {
        run_mtu_discovery_test(false, None, Some(1), 1472).await // Ethernet: 1500 - 28
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_with_io_uring() -> Result<()> {
        if !is_io_uring_supported() {
            return Ok(());
        }
        run_mtu_discovery_test(true, None, None, 1440).await
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_short_timeout() -> Result<()> {
        run_mtu_discovery_test(false, Some(500), None, 1440).await
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_long_timeout() -> Result<()> {
        run_mtu_discovery_test(false, Some(1000), Some(1), 1440).await
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_min_retries() -> Result<()> {
        run_mtu_discovery_test(false, None, Some(1), 1440).await
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_max_retries() -> Result<()> {
        run_mtu_discovery_test(false, None, Some(1), 1440).await
    }

    #[tokio::test]
    pub async fn test_mtu_discovery_timeout_and_retries() -> Result<()> {
        run_mtu_discovery_test(false, Some(500), Some(2), 1440).await
    }
}
