#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, TestEnvironment};
    use anyhow::Result;
    use test_log::test;
    use tracing::{info, warn};

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_single_stream_echo_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting single stream echo test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44433"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44433",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "aaaa1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/basic_echo_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_parallel_stream_echo_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting parallel stream echo test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44434"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44434",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "bbbb1baa11",
            "--alpn",
            "echo",
            "--echo-stream-number",
            "3",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/basic_echo_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_large_payload_echo_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting large payload echo test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44435"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44435",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "cccc1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
            "--ssl-key-log",
            "./my_quic.log",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_parallel_large_payload_echo_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!(
            "Starting parallel stream large payload echo test{}...",
            io_uring_str
        );

        let server_config = ["--listen", "127.0.0.1:44434"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44434",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "bbbb1baa11",
            "--alpn",
            "echo",
            "--echo-stream-number",
            "3",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_long_message_echo_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting long message echo test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44435"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44435",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "cccc1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/long_message_input",
            "--ssl-key-log",
            "./my_quic.log",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_parallel_long_message_echo_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!(
            "Starting parallel stream long message echo test{}...",
            io_uring_str
        );

        let server_config = ["--listen", "127.0.0.1:44434"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44434",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "bbbb1baa11",
            "--alpn",
            "echo",
            "--echo-stream-number",
            "3",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/long_message_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_parallel_long_message_echo_with_packet_loss_test(
        use_io_uring: bool,
    ) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!(
            "Starting parallel stream long message echo test with packet loss{}...",
            io_uring_str
        );

        let server_config = ["--listen", "127.0.0.1:44434"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44434",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "bbbb1baa11",
            "--alpn",
            "echo",
            "--echo-stream-number",
            "3",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/long_message_input",
            "--recv-loss-rate",
            "0.1",
            "--send-loss-rate",
            "0.1",
            "--ssl-key-log",
            "./my_quic.log",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_connection_data_limit_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting connection data limit test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44436", "--max-data", "256"];
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
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_stream_data_limit_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting stream data limit test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44437", "--max-stream-data", "256"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44437",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "dddd1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 15)
            .await;

        test_env.cleanup().await?;
        test_result
    }

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_connection_data_blocking_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting connection data blocking test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44438", "--max-data", "0"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44438",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "dddd1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "was sent blocked",
        ];

        let failure_patterns = [
            "Echo verification successful for stream",
            "All streams finished, exiting",
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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_stream_data_blocking_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting stream data blocking test{}...", io_uring_str);

        let server_config = ["--listen", "127.0.0.1:44439", "--max-stream-data", "0"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44439",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "dddd1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "was sent blocked",
        ];

        let failure_patterns = [
            "Echo verification successful for stream",
            "All streams finished, exiting",
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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_bidirectional_stream_blocking_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!(
            "Starting bidirectional stream blocking test{}...",
            io_uring_str
        );

        let server_config = ["--listen", "127.0.0.1:44439", "--max-bidi-streams", "0"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44439",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "dddd1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "due to streams limitation",
        ];

        let failure_patterns = [
            "Echo verification successful for stream",
            "All streams finished, exiting",
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

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_large_payload_with_packet_loss_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!(
            "Starting large payload echo test with packet loss simulation{}...",
            io_uring_str
        );

        let server_config = ["--listen", "127.0.0.1:44440"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44440",
            "--sni",
            "localhost",
            "--first-initial-packet-size",
            "1200",
            "--scid",
            "cccc1baa11",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/large_payload_input",
            "--recv-loss-rate",
            "0.1",
            "--send-loss-rate",
            "0.1",
            "--ssl-key-log",
            "./my_quic.log",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

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

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_single_stream_echo() -> Result<()> {
        run_single_stream_echo_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_stream_echo() -> Result<()> {
        run_parallel_stream_echo_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_large_payload_echo() -> Result<()> {
        run_large_payload_echo_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_large_payload_echo() -> Result<()> {
        run_parallel_large_payload_echo_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_long_message_echo() -> Result<()> {
        run_long_message_echo_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_long_message_echo() -> Result<()> {
        run_parallel_long_message_echo_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_long_message_echo_with_packet_loss() -> Result<()> {
        run_parallel_long_message_echo_with_packet_loss_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_connection_data_limit() -> Result<()> {
        run_connection_data_limit_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_stream_data_limit() -> Result<()> {
        run_stream_data_limit_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_connection_data_blocking() -> Result<()> {
        run_connection_data_blocking_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_stream_data_blocking() -> Result<()> {
        run_stream_data_blocking_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_bidirectional_stream_blocking() -> Result<()> {
        run_bidirectional_stream_blocking_test(false).await
    }

    // Original test function, calls the generic test function without io_uring
    #[test(tokio::test)]
    pub async fn test_large_payload_with_packet_loss() -> Result<()> {
        run_large_payload_with_packet_loss_test(false).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_single_stream_echo_io_uring() -> Result<()> {
        run_single_stream_echo_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_stream_echo_io_uring() -> Result<()> {
        run_parallel_stream_echo_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_large_payload_echo_io_uring() -> Result<()> {
        run_large_payload_echo_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_large_payload_echo_io_uring() -> Result<()> {
        run_parallel_large_payload_echo_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_long_message_echo_io_uring() -> Result<()> {
        run_long_message_echo_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_long_message_echo_io_uring() -> Result<()> {
        run_parallel_long_message_echo_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_parallel_long_message_echo_with_packet_loss_io_uring() -> Result<()> {
        run_parallel_long_message_echo_with_packet_loss_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_connection_data_limit_io_uring() -> Result<()> {
        run_connection_data_limit_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_stream_data_limit_io_uring() -> Result<()> {
        run_stream_data_limit_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_connection_data_blocking_io_uring() -> Result<()> {
        run_connection_data_blocking_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_stream_data_blocking_io_uring() -> Result<()> {
        run_stream_data_blocking_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_bidirectional_stream_blocking_io_uring() -> Result<()> {
        run_bidirectional_stream_blocking_test(true).await
    }

    // Test function that uses io_uring
    #[test(tokio::test)]
    pub async fn test_large_payload_with_packet_loss_io_uring() -> Result<()> {
        run_large_payload_with_packet_loss_test(true).await
    }
}
