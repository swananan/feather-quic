use crate::utils::{init_logging, TestEnvironment};
use anyhow::Result;
use test_log::test;
use tracing::{info, warn};

#[test(tokio::test)]
pub async fn test_echo() -> Result<()> {
    init_logging();
    info!("Starting single stream echo test...");

    let server_args = ["--listen", "127.0.0.1:44433"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file",
        // "--idle-timeout",
        // "5000",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let unexpected_patterns = [];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;

    result
}

#[test(tokio::test)]
pub async fn test_multi_stream() -> Result<()> {
    init_logging();
    info!("Starting multi-stream echo test...");

    let server_args = ["--listen", "127.0.0.1:44434"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file",
        // "--idle-timeout",
        // "5000",
        // Only for debug
        // "--ssl-key-log",
        // "./my_quic.log",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let unexpected_patterns = [];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;

    result
}

#[test(tokio::test)]
pub async fn test_large_echo() -> Result<()> {
    init_logging();
    info!("Starting large echo test...");

    let server_args = ["--listen", "127.0.0.1:44435"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file_large",
        // "--idle-timeout",
        // "5000",
        // Only for debug
        "--ssl-key-log",
        "./my_quic.log",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let unexpected_patterns = [];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;

    result
}

#[test(tokio::test)]
pub async fn test_max_data_limit() -> Result<()> {
    init_logging();
    info!("Starting max data limit test...");

    let server_args = ["--listen", "127.0.0.1:44436", "--max-data", "256"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file_large",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let unexpected_patterns = [];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;
    result
}

#[test(tokio::test)]
pub async fn test_max_stream_data_limit() -> Result<()> {
    init_logging();
    info!("Starting max stream data limit test...");

    let server_args = ["--listen", "127.0.0.1:44437", "--max-stream-data", "256"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file_large",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let unexpected_patterns = [];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    env.cleanup().await?;
    result
}

#[test(tokio::test)]
pub async fn test_max_data_blocked() -> Result<()> {
    init_logging();
    info!("Starting max data blocked test...");

    let server_args = ["--listen", "127.0.0.1:44438", "--max-data", "0"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file_large",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "was sent blocked",
    ];

    let unexpected_patterns = [
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;
    result
}

#[test(tokio::test)]
pub async fn test_max_stream_data_blocked() -> Result<()> {
    init_logging();
    info!("Starting max stream data blocked test...");

    let server_args = ["--listen", "127.0.0.1:44439", "--max-stream-data", "0"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file_large",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "was sent blocked",
    ];

    let unexpected_patterns = [
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;
    result
}

#[test(tokio::test)]
pub async fn test_max_streams_bi_blocked() -> Result<()> {
    init_logging();
    info!("Starting max streams bi blocked test...");

    let server_args = ["--listen", "127.0.0.1:44439", "--max-bidi-streams", "0"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file_large",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "due to streams limitation",
    ];

    let unexpected_patterns = [
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;
    result
}

#[test(tokio::test)]
pub async fn test_large_echo_with_lossy() -> Result<()> {
    init_logging();
    info!("Starting large echo test with lossy...");

    let server_args = ["--listen", "127.0.0.1:44440"];
    let mut env = TestEnvironment::setup(&server_args).await?;

    let client_args = [
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
        "feather-quic-integration-tests/src/tests/test_files/echo_test_file_large",
        "--recv-loss-rate",
        "0.1",
        "--send-loss-rate",
        "0.1",
        // "--idle-timeout",
        // "5000",
        // Only for debug
        "--ssl-key-log",
        "./my_quic.log",
    ];

    let expected_patterns = [
        "QUIC connection established successfully",
        "Echo verification successful for stream",
        "All streams finished, exiting",
    ];

    let unexpected_patterns = [];

    let result = env
        .run_client_test(&client_args, &expected_patterns, &unexpected_patterns, 15)
        .await;

    if let Err(e) = &result {
        warn!("Test failed. Error: {}", e);
        env.test_failed = true;
    }

    env.cleanup().await?;

    result
}
