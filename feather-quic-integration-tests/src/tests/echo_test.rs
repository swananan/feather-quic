use anyhow::Result;
use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use test_log::test;

#[test(tokio::test)]
pub async fn test_echo() -> Result<()> {
    // Get the workspace root directory (parent of the current package)
    let current_dir = env::current_dir()?;
    let workspace_root = current_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get workspace root directory"))?;

    // Build both required binaries from workspace root
    let build_output = Command::new("cargo")
        .current_dir(workspace_root)
        .arg("build")
        .arg("--bin")
        .arg("echo_server")
        .arg("--bin")
        .arg("feather_quic_client_tool")
        .output()?;

    if !build_output.status.success() {
        let stderr = String::from_utf8_lossy(&build_output.stderr);
        return Err(anyhow::anyhow!("Failed to build binaries: {}", stderr));
    }

    // Get the target directory
    let target_dir = workspace_root.join("target").join("debug");

    // Verify both binaries exist
    let server_binary = target_dir.join("echo_server");
    let client_binary = target_dir.join("feather-quic-client-tool");

    if !server_binary.exists() || !client_binary.exists() {
        return Err(anyhow::anyhow!(
            "Binaries not found. Server: {:?}, Client: {:?}. Build output: {}",
            server_binary,
            client_binary,
            String::from_utf8_lossy(&build_output.stdout)
        ));
    }

    // Start server in background with explicit address
    let mut server = Command::new(&server_binary)
        .arg("--listen")
        .arg("127.0.0.1:4433")
        .spawn()?;

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client with test message using feather-quic-client-tool
    let output = Command::new(&client_binary)
        .arg("--target-address")
        .arg("127.0.0.1:4433")
        .arg("--echo")
        .arg("Hello, QUIC!")
        .output()?;

    // Verify output
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Server response: Hello, QUIC!"));

    // Cleanup
    server.kill()?;

    Ok(())
}
