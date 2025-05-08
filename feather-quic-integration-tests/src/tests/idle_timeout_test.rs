#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, platform::is_io_uring_supported, TestEnvironment};
    use anyhow::{anyhow, Result};
    use tracing::{info, warn};

    // Generic test function that accepts a parameter to determine whether to use io_uring
    async fn run_idle_timeout_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting idle timeout test{}...", io_uring_str);

        let server_config = vec!["--listen", "127.0.0.1:44433", "--wait-only"];

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
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Should shut down QUIC connection, due to idle timeout",
        ];

        let failure_patterns = [];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 15)
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
    pub async fn test_idle_timeout() -> Result<()> {
        run_idle_timeout_test(false).await
    }

    #[tokio::test]
    pub async fn test_idle_timeout_io_uring() -> Result<()> {
        if !is_io_uring_supported() {
            return Ok(());
        }
        run_idle_timeout_test(true).await
    }
}
