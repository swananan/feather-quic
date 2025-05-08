#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, platform::is_io_uring_supported, TestEnvironment};
    use anyhow::{anyhow, Result};
    use tracing::{info, warn};

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_close_connection_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting close connection test{}...", io_uring_str);

        // Configure server to close connection after 1 stream
        let server_config = ["--listen", "127.0.0.1:44437", "--close-after-streams", "1"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44437",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "dddd1baa12",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/basic_echo_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        // We expect to see connection closed after 3 messages
        let success_patterns = [
            "QUIC connection established successfully",
            "Entering draining",
            "QUIC connection close callback",
            "closed after reaching stream limit",
        ];

        let failure_patterns = [
            "All streams finished, exiting", // We don't expect this since connection should be closed
        ];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 4)
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

    #[tokio::test]
    pub async fn test_close_connection() -> Result<()> {
        run_close_connection_test(false).await
    }

    #[tokio::test]
    pub async fn test_close_connection_io_uring() -> Result<()> {
        if !is_io_uring_supported() {
            return Ok(());
        }
        run_close_connection_test(true).await
    }
}
