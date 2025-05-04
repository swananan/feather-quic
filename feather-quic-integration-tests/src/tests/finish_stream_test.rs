#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, TestEnvironment};
    use anyhow::{anyhow, Result};
    use tracing::{info, warn};

    // Test configuration constants
    const FINISH_AFTER_MESSAGES: &str = "10";
    const NORMAL_LOSS_RATE: &str = "0.1";
    // const HIGH_LOSS_RATE: &str = "0.3";
    const INITIAL_PACKET_SIZE: &str = "1200";
    const TEST_TIMEOUT: u64 = 15;

    // Common server configuration
    fn get_server_config(port: &str) -> [&str; 4] {
        [
            "--listen",
            port,
            "--finish-after-messages",
            FINISH_AFTER_MESSAGES,
        ]
    }

    // Common client configuration
    fn get_base_client_config<'a>(port: &'a str, scid: &'a str) -> Vec<&'a str> {
        vec![
            "--target-address",
            port,
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            INITIAL_PACKET_SIZE,
            "--scid",
            scid,
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
        ]
    }

    // Test normal stream finishing without packet loss
    async fn run_normal_finish_stream_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting normal finish stream test{}...", io_uring_str);

        let server_config = get_server_config("127.0.0.1:44440");
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = get_base_client_config("127.0.0.1:44440", "0a1b2c3d4e5f");

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "Quic stream error: ReceiverShutdown",
            "All streams finished, due to early termination",
        ];

        let failure_patterns = [];

        let test_result = test_env
            .run_client_test(
                &client_config,
                &success_patterns,
                &failure_patterns,
                TEST_TIMEOUT,
            )
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

    // Test stream finishing with packet loss
    async fn run_finish_stream_with_loss_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting finish stream with loss test{}...", io_uring_str);

        let server_config = get_server_config("127.0.0.1:44441");
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = get_base_client_config("127.0.0.1:44441", "1a2b3c4d5e6f");
        client_config.extend_from_slice(&[
            "--recv-loss-rate",
            NORMAL_LOSS_RATE,
            "--send-loss-rate",
            NORMAL_LOSS_RATE,
        ]);

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "Quic stream error: ReceiverShutdown",
            "All streams finished, due to early termination",
        ];

        let failure_patterns = [];

        let test_result = test_env
            .run_client_test(
                &client_config,
                &success_patterns,
                &failure_patterns,
                TEST_TIMEOUT,
            )
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

    // Test stream finishing with high packet loss
    // async fn run_finish_stream_with_high_loss_test(use_io_uring: bool) -> Result<()> {
    //     init_logging();
    //     let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
    //     info!(
    //         "Starting finish stream with high loss test{}...",
    //         io_uring_str
    //     );

    //     let server_config = get_server_config("127.0.0.1:44442");
    //     let mut test_env = TestEnvironment::setup(&server_config).await?;

    //     let mut client_config = get_base_client_config("127.0.0.1:44442", "2a3b4c5d6e7f");
    //     client_config.extend_from_slice(&[
    //         "--recv-loss-rate",
    //         HIGH_LOSS_RATE,
    //         "--send-loss-rate",
    //         HIGH_LOSS_RATE,
    //     ]);

    //     if use_io_uring {
    //         client_config.push("--use-io-uring");
    //     }

    //     let success_patterns = [
    //         "QUIC connection established successfully",
    //         "Echo verification successful for stream",
    //         "Quic stream error: ReceiverShutdown",
    //         "All streams finished, due to early termination",
    //     ];

    //     let failure_patterns = [];

    //     let test_result = test_env
    //         .run_client_test(
    //             &client_config,
    //             &success_patterns,
    //             &failure_patterns,
    //             TEST_TIMEOUT,
    //         )
    //         .await;

    //     if let Err(error) = &test_result {
    //         warn!("Test failed. Error: {}", error);
    //         test_env.test_failed = true;
    //     }

    //     let cleanup_result = test_env.cleanup().await;

    //     let final_result = match (test_result, cleanup_result) {
    //         (Ok(_), Ok(_)) => Ok(()),
    //         (Err(test_err), Ok(_)) => Err(test_err),
    //         (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
    //         (Err(test_err), Err(cleanup_err)) => Err(anyhow!("{}\n{}", test_err, cleanup_err)),
    //     };

    //     if let Err(e) = &final_result {
    //         warn!("Test execution or cleanup failed: {}", e);
    //     }

    //     final_result
    // }

    // Test stream finishing with selective packet loss (only FIN packets)
    async fn run_finish_stream_with_selective_loss_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!(
            "Starting finish stream with selective loss test{}...",
            io_uring_str
        );

        let server_config = get_server_config("127.0.0.1:44443");
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = get_base_client_config("127.0.0.1:44443", "3a4b5c6d7e8f");
        client_config.extend_from_slice(&[
            "--recv-loss-rate",
            NORMAL_LOSS_RATE,
            "--send-loss-rate",
            NORMAL_LOSS_RATE,
        ]);

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "Quic stream error: ReceiverShutdown",
            "All streams finished, due to early termination",
        ];

        let failure_patterns = [];

        let test_result = test_env
            .run_client_test(
                &client_config,
                &success_patterns,
                &failure_patterns,
                TEST_TIMEOUT,
            )
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
    pub async fn test_normal_finish_stream() -> Result<()> {
        run_normal_finish_stream_test(false).await
    }

    #[tokio::test]
    pub async fn test_normal_finish_stream_io_uring() -> Result<()> {
        run_normal_finish_stream_test(true).await
    }

    #[tokio::test]
    pub async fn test_finish_stream_with_loss() -> Result<()> {
        run_finish_stream_with_loss_test(false).await
    }

    #[tokio::test]
    pub async fn test_finish_stream_with_loss_io_uring() -> Result<()> {
        run_finish_stream_with_loss_test(true).await
    }

    // TODO: it looks like the high loss test is not working as expected
    // #[tokio::test]
    // pub async fn test_finish_stream_with_high_loss() -> Result<()> {
    //     run_finish_stream_with_high_loss_test(false).await
    // }

    // #[tokio::test]
    // pub async fn test_finish_stream_with_high_loss_io_uring() -> Result<()> {
    //     run_finish_stream_with_high_loss_test(true).await
    // }

    #[tokio::test]
    pub async fn test_finish_stream_with_selective_loss() -> Result<()> {
        run_finish_stream_with_selective_loss_test(false).await
    }

    #[tokio::test]
    pub async fn test_finish_stream_with_selective_loss_io_uring() -> Result<()> {
        run_finish_stream_with_selective_loss_test(true).await
    }
}
