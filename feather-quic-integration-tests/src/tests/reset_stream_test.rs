#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, TestEnvironment};
    use anyhow::Result;
    use tracing::{info, warn};

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_reset_stream_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting reset stream test{}...", io_uring_str);

        // Configure server to reset after 3 messages
        let server_config = ["--listen", "127.0.0.1:44436", "--reset-after-messages", "3"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44436",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "dddd1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/basic_echo_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        // We expect to see stream reset error after 3 messages
        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "Quic stream error: ReceiverReset(8)",
        ];

        let failure_patterns = [
            "All streams finished, exiting", // We don't expect this since stream should be reset
        ];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 15)
            .await;

        if let Err(error) = &test_result {
            warn!("Test failed. Error: {}", error);
            test_env.test_failed = true;
        }

        test_env.cleanup().await?;

        test_result
    }

    #[tokio::test]
    pub async fn test_reset_stream() -> Result<()> {
        run_reset_stream_test(false).await
    }

    #[tokio::test]
    pub async fn test_reset_stream_io_uring() -> Result<()> {
        run_reset_stream_test(true).await
    }
}
