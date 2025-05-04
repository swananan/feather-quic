#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, TestEnvironment};
    use anyhow::{anyhow, Result};
    use tracing::{info, warn};

    async fn run_connect_failure_wrong_alpn_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting idle timeout test{}...", io_uring_str);

        let server_config = vec!["--listen", "127.0.0.1:44433"];

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
            "ECHO",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/basic_echo_input",
            "--idle-timeout",
            "5000", // 3 seconds
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection establishment failed, due to",
            "peer doesn't support any known protocol",
        ];

        let failure_patterns = ["QUIC connection established successfully"];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 5)
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

    async fn run_connect_failure_idle_timeout_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting idle timeout test{}...", io_uring_str);

        let server_config = vec!["--listen", "127.0.0.1:44433"];

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
            "--idle-timeout",
            "3000", // 3 seconds
            "--send-loss-rate",
            "1.0",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = ["QUIC connection establishment timed out after 3000ms"];

        let failure_patterns = ["QUIC connection established successfully"];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 5)
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
    pub async fn test_connect_failure_idle_timeout() -> Result<()> {
        run_connect_failure_idle_timeout_test(false).await
    }

    #[tokio::test]
    pub async fn test_connect_failure_idle_timeout_io_uring() -> Result<()> {
        run_connect_failure_idle_timeout_test(true).await
    }

    #[tokio::test]
    pub async fn test_connect_failure_wrong_alpn() -> Result<()> {
        run_connect_failure_wrong_alpn_test(false).await
    }

    #[tokio::test]
    pub async fn test_connect_failure_wrong_alpn_io_uring() -> Result<()> {
        run_connect_failure_wrong_alpn_test(true).await
    }
}
