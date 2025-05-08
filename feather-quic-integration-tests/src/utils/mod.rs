use anyhow::{anyhow, Result};
use chrono::Local;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::process::{Child, Command};
use tracing::{debug, info, warn, Level};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::FmtSubscriber;

pub mod platform;

static INIT: Once = Once::new();
static INIT_SUCCESS: AtomicBool = AtomicBool::new(false);
static BUILD_ONCE: Once = Once::new();

struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        let now = Local::now();
        write!(w, "{}", now.format("%Y-%m-%d %H:%M:%S.%3f"))
    }
}

pub fn init_logging() {
    if !INIT_SUCCESS.load(Ordering::SeqCst) {
        INIT.call_once(|| {
            let subscriber = FmtSubscriber::builder()
                .with_timer(LocalTimer)
                .with_target(false)
                .with_file(true)
                .with_line_number(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_ansi(true)
                .with_level(true)
                .with_max_level(Level::DEBUG)
                .finish();

            if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
                warn!("Failed to set tracing subscriber: {}", e);
            } else {
                INIT_SUCCESS.store(true, Ordering::SeqCst);
            }
        });
    }
}

pub struct TestEnvironment {
    pub workspace_root: PathBuf,
    pub server_binary: PathBuf,
    pub client_binary: PathBuf,
    pub server: Child,
    pub test_failed: bool,
    pub server_log_file: NamedTempFile,
    pub print_to_stdout: bool,
}

impl TestEnvironment {
    pub async fn setup(server_args: &[&str]) -> Result<Self> {
        // Get the workspace root directory
        let current_dir = env::current_dir()?;
        let workspace_root = current_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Could not get workspace root directory"))?
            .to_path_buf();
        debug!("Workspace root: {:?}", workspace_root);

        // Check if we should print to stdout
        let print_to_stdout =
            env::var("PRINT_TO_STDOUT").unwrap_or_else(|_| "0".to_string()) == "1";

        // Build both required binaries
        info!("Building required binaries...");
        let mut build_output = None;
        if !BUILD_ONCE.is_completed() {
            let output = Command::new("cargo")
                .current_dir(&workspace_root)
                .arg("build")
                .arg("--bin")
                .arg("echo-server")
                .arg("--bin")
                .arg("feather-quic-client-tool")
                .output()
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Build failed with stderr: {}", stderr);
                return Err(anyhow::anyhow!("Failed to build binaries: {}", stderr));
            }
            debug!("Build successful");
            BUILD_ONCE.call_once(|| {});
            build_output = Some(output)
        } else {
            debug!("Binaries already built, skipping build step");
        }

        // Get the target directory
        let target_dir = workspace_root.join("target").join("debug");

        // Verify both binaries exist
        let server_binary = target_dir.join("echo-server");
        let client_binary = target_dir.join("feather-quic-client-tool");

        if !server_binary.exists() || !client_binary.exists() {
            warn!(
                "Binaries not found. Server: {:?}, Client: {:?}",
                server_binary, client_binary
            );
            return Err(anyhow::anyhow!(
                "Binaries not found. Server: {:?}, Client: {:?}. Build output: {}",
                server_binary,
                client_binary,
                String::from_utf8_lossy(&build_output.map(|p| p.stdout).unwrap_or(vec![]))
            ));
        }

        // Create a temporary file for server logs
        let server_log_file = NamedTempFile::new()?;
        let server_log_path = server_log_file.path().to_str().unwrap();

        // Start server with provided arguments
        info!("Starting echo server with args: {:?}", server_args);
        let mut server_cmd = Command::new(&server_binary);
        server_cmd
            .env("RUST_LOG", "trace")
            .args(server_args)
            .arg("--log-file")
            .arg(server_log_path);

        let server = match server_cmd.spawn() {
            Ok(server) => server,
            Err(_e) => {
                // If server fails to start, persist the log file
                let persist_path = workspace_root.join(format!(
                    "server_start_failed_{}.log",
                    chrono::Utc::now().timestamp()
                ));
                fs::copy(server_log_path, &persist_path)?;
                warn!(
                    "Server failed to start. Log file saved to: {}",
                    persist_path.display()
                );
                return Err(anyhow!(
                    "Server failed to start. See log file: {}",
                    persist_path.display()
                ));
            }
        };

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(TestEnvironment {
            workspace_root,
            server_binary,
            client_binary,
            server,
            test_failed: false,
            server_log_file,
            print_to_stdout,
        })
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        info!("Cleaning up test environment...");

        // Kill the server process
        if let Err(e) = self.server.kill().await {
            warn!("Failed to kill server process: {}", e);
        }

        // Take ownership of the server process
        let mut server = std::mem::replace(&mut self.server, Command::new("true").spawn()?);

        // Wait for server to exit
        let _ = server.wait().await;

        // Only save server logs if test failed
        if self.test_failed {
            // Read and print server logs if requested
            if self.print_to_stdout {
                let log_content = fs::read_to_string(self.server_log_file.path())?;
                println!("=== Server Logs ===");
                println!("{}", log_content);
                println!("==================");
            } else {
                let persist_path = self.workspace_root.join(format!(
                    "server_test_failed_{}.log",
                    chrono::Utc::now().timestamp()
                ));
                let log_path = self.server_log_file.path();
                fs::copy(log_path, &persist_path)?;
                info!("Server logs saved to: {}", persist_path.display());
                return Err(anyhow!("See server log file: {}", persist_path.display()));
            }
        }

        Ok(())
    }

    pub async fn run_client_test(
        &mut self,
        client_args: &[&str],
        expected_patterns: &[&str],
        unexpected_patterns: &[&str],
        timeout_secs: u64,
    ) -> Result<()> {
        // Create a temporary file for logs
        let log_file = NamedTempFile::new()?;
        let log_path = log_file.path().to_str().unwrap();

        info!("Starting client with args: {:?}", client_args);
        let mut client_cmd = Command::new(&self.client_binary);

        let mut client_process = client_cmd
            .current_dir(&self.workspace_root)
            .env("RUST_LOG", "trace")
            .env("RUST_BACKTRACE", "1")
            .args(client_args)
            .arg("--log-file")
            .arg(log_path)
            .spawn()?;

        let client_output =
            tokio::time::timeout(Duration::from_secs(timeout_secs), client_process.wait()).await;

        let mut test_failed = match client_output {
            Ok(Ok(status)) => {
                if !status.success() {
                    warn!("Client process failed with status: {}", status);
                    true
                } else {
                    false
                }
            }
            Ok(Err(e)) => {
                warn!("Client process failed: {}", e);
                true
            }
            Err(_) => {
                warn!("Client process timed out after {} seconds", timeout_secs);
                if let Err(e) = client_process.kill().await {
                    warn!("Failed to kill client process: {}", e);
                }
                true
            }
        };

        // Read the log file and check for expected patterns and errors
        let log_content = fs::read_to_string(log_path)?;

        let mut missing_patterns = Vec::new();
        for pattern in expected_patterns {
            if !log_content.contains(pattern) {
                missing_patterns.push(*pattern);
                warn!("Missing expected pattern: {}", pattern);
            }
        }

        let mut unwanted_patterns = Vec::new();
        for pattern in unexpected_patterns {
            if log_content.contains(pattern) {
                unwanted_patterns.push(*pattern);
                warn!("Got unexpected pattern: {}", pattern);
            }
        }

        // Check for error logs
        if log_content.contains("ERROR") {
            warn!("Error logs found in the log file");
            test_failed = true;
        }

        if !missing_patterns.is_empty() {
            warn!(
                "Output verification failed. Missing expected patterns: {:?}",
                missing_patterns
            );
            test_failed = true;
        }

        if !unwanted_patterns.is_empty() {
            warn!(
                "Output verification failed. Finding expected patterns: {:?}",
                unwanted_patterns
            );
            test_failed = true;
        }

        // If test failed, persist the log file
        if test_failed {
            // Print logs to stdout if requested
            if self.print_to_stdout {
                println!("=== Client Logs ===");
                println!("{}", log_content);
                println!("==================");
            } else {
                let persist_path = self.workspace_root.join(format!(
                    "client_test_failed_{}.log",
                    chrono::Utc::now().timestamp()
                ));
                fs::copy(log_path, &persist_path)?;
                return Err(anyhow::anyhow!(
                    "Test failed\nSee client log file: {}",
                    persist_path.display()
                ));
            }
        }

        Ok(())
    }
}
