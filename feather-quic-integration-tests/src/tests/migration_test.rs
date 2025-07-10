#[cfg(test)]
mod tests {
    use crate::utils::{init_logging, platform::is_io_uring_supported, TestEnvironment};
    use anyhow::{anyhow, Result};
    use test_log::test;
    use tracing::{info, warn};

    /// Test preferred address migration with IPv4 preferred address
    async fn run_preferred_address_migration_ipv4_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!(
            "Starting preferred address migration IPv4 test{}...",
            io_uring_str
        );

        // Configure server with preferred address support
        let server_config = [
            "--listen",
            "127.0.0.1:44440",
            "--enable-preferred-address",
            "--preferred-ipv4-addr",
            "127.0.0.1:44441",
        ];

        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44440",
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
            "--ssl-key-log",
            "./my_quic.log",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Echo verification successful for stream",
            "Path 1 validation completed successfully",
            "Migration Callback: to preferred address success: 0 -> 1",
            "All streams finished, exiting",
        ];

        let failure_patterns = [];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 20)
            .await;

        if let Err(error) = &test_result {
            warn!(
                "Preferred address IPv4 migration test failed. Error: {}",
                error
            );
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
            warn!(
                "Preferred address IPv4 migration test execution or cleanup failed: {}",
                e
            );
        }

        final_result
    }

    /// Test server starts correctly with IPv4 preferred address endpoint
    async fn run_preferred_address_server_startup_test() -> Result<()> {
        init_logging();
        info!("Starting preferred address server startup test...");

        // Configure server with IPv4 preferred address support
        let server_config = [
            "--listen",
            "127.0.0.1:44447",
            "--enable-preferred-address",
            "--preferred-ipv4-addr",
            "127.0.0.1:44448",
        ];

        let mut test_env = TestEnvironment::setup(&server_config).await?;

        // Just verify server starts up correctly, no client connection needed
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        info!("Server startup test completed successfully");

        test_env.cleanup().await?;

        Ok(())
    }

    /// Test client-initiated migration to extra rebind address
    async fn run_client_active_migration_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let io_uring_str = if use_io_uring { " with io_uring" } else { "" };
        info!("Starting client active migration test{}...", io_uring_str);

        // Server listens on 127.0.0.1:44500, extra rebind to 127.0.0.1:44501
        let server_config = [
            "--listen",
            "127.0.0.1:44500",
            "--extra-rebind-addr",
            "127.0.0.1:44501",
        ];

        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            "127.0.0.1:44500",
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
            "--ssl-key-log",
            "./my_quic.log",
            "--migrate-to-addr",
            "127.0.0.1:44501",
        ];

        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let success_patterns = [
            "QUIC connection established successfully",
            "Attempting migration to address: 127.0.0.1:44501",
            "Migration Callback: switch success:",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];

        let failure_patterns = ["Migration Callback: switch failed:", "ERROR"];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 20)
            .await;

        if let Err(error) = &test_result {
            warn!("Client active migration test failed. Error: {}", error);
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
            warn!(
                "Client active migration test execution or cleanup failed: {}",
                e
            );
        }

        final_result
    }

    async fn run_client_migration_to_nonexistent_addr_test(use_io_uring: bool) -> Result<()> {
        init_logging();
        let (server_port, client_migrate_port) = if use_io_uring {
            (44610, 44611)
        } else {
            (44600, 44601)
        };
        let server_addr = format!("127.0.0.1:{server_port}");
        let migrate_addr = format!("127.0.0.1:{client_migrate_port}");
        let server_config = ["--listen", &server_addr, "--echo-wait", "1:1400"];
        let mut test_env = TestEnvironment::setup(&server_config).await?;

        let mut client_config = vec![
            "--target-address",
            &server_addr,
            "--sni",
            "localhost",
            "--alpn",
            "echo",
            "-e",
            "feather-quic-integration-tests/src/tests/test_files/basic_echo_input",
            "--migrate-to-addr",
            &migrate_addr,
            "--ssl-key-log",
            "./my_quic.log",
        ];
        if use_io_uring {
            client_config.push("--use-io-uring");
        }

        let attempt_pattern = format!("Attempting migration to address: {migrate_addr}");
        let success_patterns = [
            "QUIC connection established successfully",
            &attempt_pattern,
            "Migration Callback: switch failed:",
            "Echo verification successful for stream",
            "All streams finished, exiting",
        ];
        let failure_patterns = ["panic", "thread '"];

        let test_result = test_env
            .run_client_test(&client_config, &success_patterns, &failure_patterns, 20)
            .await;

        if let Err(_error) = &test_result {
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
            warn!(
                "Client migration to nonexistent address test execution or cleanup failed: {}",
                e
            );
        }

        final_result
    }

    #[test(tokio::test)]
    pub async fn test_client_migration_to_nonexistent_addr() -> Result<()> {
        run_client_migration_to_nonexistent_addr_test(false).await
    }

    #[test(tokio::test)]
    pub async fn test_client_migration_to_nonexistent_addr_io_uring() -> Result<()> {
        if !is_io_uring_supported() {
            info!("io_uring is not supported on this platform, skipping test");
            return Ok(());
        }
        run_client_migration_to_nonexistent_addr_test(true).await
    }

    #[test(tokio::test)]
    pub async fn test_preferred_address_server_startup() -> Result<()> {
        run_preferred_address_server_startup_test().await
    }

    #[test(tokio::test)]
    pub async fn test_preferred_address_migration_ipv4() -> Result<()> {
        run_preferred_address_migration_ipv4_test(false).await
    }

    #[test(tokio::test)]
    pub async fn test_preferred_address_migration_ipv4_io_uring() -> Result<()> {
        if !is_io_uring_supported() {
            info!("io_uring is not supported on this platform, skipping test");
            return Ok(());
        }
        run_preferred_address_migration_ipv4_test(true).await
    }

    #[test(tokio::test)]
    pub async fn test_client_active_migration() -> Result<()> {
        run_client_active_migration_test(false).await
    }

    #[test(tokio::test)]
    pub async fn test_client_active_migration_io_uring() -> Result<()> {
        if !is_io_uring_supported() {
            info!("io_uring is not supported on this platform, skipping test");
            return Ok(());
        }
        run_client_active_migration_test(true).await
    }
}
