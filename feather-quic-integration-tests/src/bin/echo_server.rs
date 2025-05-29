use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use quinn::{Endpoint, ServerConfig};
use quinn_proto::{crypto::rustls::QuicServerConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use tokio::{task::JoinHandle, time::sleep};
use tracing::{error, info, info_span, trace};
use tracing_futures::Instrument as _;
use tracing_subscriber::EnvFilter;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"echo"];

#[derive(Parser, Debug, Clone)]
#[clap(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[clap(long = "keylog")]
    keylog: bool,
    /// Enable mandatory retry validation during handshake. When enabled, the server will require all connections to validate their address through a retry process.
    #[clap(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::1]:4433")]
    listen: SocketAddr,
    /// Client address to block
    #[clap(long = "block")]
    block: Option<SocketAddr>,
    /// Maximum number of concurrent connections to allow
    #[clap(long = "connection-limit")]
    connection_limit: Option<usize>,
    /// Maximum number of concurrent bidirectional streams
    #[clap(long = "max-bidi-streams", default_value = "100")]
    max_bidi_streams: u64,
    /// Maximum number of concurrent unidirectional streams
    #[clap(long = "max-uni-streams", default_value = "100")]
    max_uni_streams: u64,
    /// Maximum amount of data that can be sent on a local bidirectional stream (in bytes)
    #[clap(long = "max-stream-data", default_value = "1048576")]
    max_stream_data: u64,
    /// Maximum amount of data that can be sent on the connection (in bytes)
    #[clap(long = "max-data", default_value = "10485760")]
    max_data: u64,
    /// Maximum idle timeout for the connection (in milliseconds)
    #[clap(long = "max-idle-timeout", default_value = "30000")]
    max_idle_timeout: u64,
    /// Reset stream after this many echo messages (0 means never reset)
    #[clap(long = "reset-after-messages", default_value = "0")]
    reset_after_messages: usize,
    /// Finish stream after this many echo messages (0 means never finish)
    #[clap(long = "finish-after-messages", default_value = "0")]
    finish_after_messages: usize,
    /// File to write logs to (if not specified, logs go to stdout/stderr)
    #[clap(long = "log-file")]
    log_file: Option<PathBuf>,
    /// Close connection after receiving this many streams (0 means never close)
    #[clap(long = "close-after-streams", default_value = "0")]
    close_after_streams: usize,
    /// If enabled, server will just wait without doing anything
    #[clap(long = "wait-only")]
    wait_only: bool,
    /// Delay before sending each response (in milliseconds)
    #[clap(long = "response-delay", default_value = "0")]
    response_delay: u64,
}

pub fn make_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let (server_config, server_cert) = configure_server()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}

fn configure_server(
) -> Result<(ServerConfig, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.serialize_der().unwrap());
    let priv_key = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![cert_der.clone()], priv_key.into())?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    Ok((server_config, cert_der))
}

fn main() -> Result<()> {
    let opt = Opt::parse();

    // Configure logging
    let env_filter = EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()));
    if opt.log_file.is_some() {
        let file = std::fs::File::create(opt.log_file.as_ref().unwrap()).with_context(|| {
            format!(
                "Failed to create log file: {:?}",
                opt.log_file.as_ref().unwrap()
            )
        })?;

        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(env_filter)
            .with_file(true)
            .with_line_number(true)
            .with_ansi(opt.log_file.is_none())
            .with_writer(file)
            .init();
    } else {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(env_filter)
            .with_line_number(true)
            .with_ansi(true)
            .init();
    }

    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    // Initialize the crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    info!("generating self-signed certificate");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());
    let cert = cert.serialize_der().unwrap();
    let certs = vec![CertificateDer::from(cert)];
    let key = key.into();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();

    transport_config.max_concurrent_bidi_streams(
        VarInt::from_u64(options.max_bidi_streams).expect("Invalid max_bidi_streams value"),
    );
    transport_config.max_concurrent_uni_streams(
        VarInt::from_u64(options.max_uni_streams).expect("Invalid max_uni_streams value"),
    );

    transport_config.stream_receive_window(
        VarInt::from_u64(options.max_stream_data).expect("Invalid max_stream_data value"),
    );
    transport_config
        .receive_window(VarInt::from_u64(options.max_data).expect("Invalid max_data value"));

    /* transport_config.send_window(options.max_data); */
    transport_config.max_idle_timeout(Some(
        Duration::from_millis(options.max_idle_timeout).try_into()?,
    ));

    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    info!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        if options
            .connection_limit
            .is_some_and(|n| endpoint.open_connections() >= n)
        {
            info!("refusing due to open connection limit");
            conn.refuse();
        } else if Some(conn.remote_address()) == options.block {
            info!("refusing blocked client IP address");
            conn.refuse();
        } else if options.stateless_retry && !conn.remote_address_validated() {
            info!("requiring connection to validate its address");
            conn.retry().unwrap();
        } else {
            info!("accepting connection");
            let fut = handle_connection(conn, options.clone());
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    error!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Incoming, options: Opt) -> Result<()> {
    let connection = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");
        info!("Connection stats: {:?}", connection.stats());

        // Use a Vec to keep track of all active streams
        let mut active_streams: Vec<JoinHandle<()>> = Vec::new();
        let mut total_streams = 0;

        loop {
            tokio::select! {
                // Accept new streams
                stream = connection.accept_bi() => {
                    match stream {
                        Ok(stream) => {
                            info!("New bidirectional stream accepted");
                            total_streams += 1;

                            // Check if we should close the connection
                            if options.close_after_streams > 0 && total_streams >= options.close_after_streams {
                                info!("Closing connection after receiving {} streams", total_streams);
                                connection.close(VarInt::from_u32(0), b"Connection closed after reaching stream limit");
                                break;
                            }

                            let stream_options = options.clone(); // Clone options for this specific stream
                            let handle = tokio::spawn(
                                async move {
                                    if let Err(e) = handle_request(stream, stream_options).await {
                                        error!("stream failed: {reason}", reason = e.to_string());
                                    }
                                }
                                .instrument(info_span!("request")),
                            );
                            active_streams.push(handle);
                            info!("Active streams count: {}", active_streams.len());
                        }
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            info!("connection closed");
                            break;
                        }
                        Err(e) => {
                            error!("Failed to accept stream: {:?}", e);
                            return Err::<(), anyhow::Error>(anyhow::Error::from(e));
                        }
                    }
                }
                // Check for completed streams
                Some(handle) = async {
                    if !active_streams.is_empty() {
                        // Find the first completed stream
                        for i in 0..active_streams.len() {
                            if active_streams[i].is_finished() {
                                return Some(active_streams.remove(i));
                            }
                        }
                        None
                    } else {
                        None
                    }
                } => {
                    if let Err(e) = handle.await {
                        error!("stream task failed: {reason}", reason = e.to_string());
                    }
                }
            }
        }

        info!(
            "Waiting for remaining {} streams to complete",
            active_streams.len()
        );
        // Wait for all remaining streams to complete
        for handle in active_streams {
            if let Err(e) = handle.await {
                error!("stream task failed: {reason}", reason = e.to_string());
            }
        }
        Ok(())
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn handle_request(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    options: Opt,
) -> Result<()> {
    if options.wait_only {
        info!("Wait-only mode enabled, just waiting...");
        // Just wait indefinitely
        tokio::time::sleep(tokio::time::Duration::from_secs(3600 * 24 * 365)).await;
        return Ok(());
    }

    let mut buffer = Vec::with_capacity(8192); // Increased buffer size
    let mut temp_buf = [0u8; 4096]; // Increased read buffer size
    let mut message_count = 0;

    loop {
        trace!("Start to read from quic stream");
        match recv.read(&mut temp_buf).await {
            Ok(None) => {
                // Stream is closed, echo any remaining data
                if !buffer.is_empty() {
                    info!(
                        "Echoing final message: {:?}, buffer size: {}",
                        String::from_utf8_lossy(&buffer),
                        buffer.len()
                    );
                    send.write_all(&buffer)
                        .await
                        .map_err(|e| anyhow!("failed to send response: {}", e))?;
                }
                break;
            }
            Ok(Some(n)) => {
                buffer.extend_from_slice(&temp_buf[..n]);

                // Process all complete lines in the buffer
                while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                    // Split at newline
                    let (line, rest) = buffer.split_at(pos + 1);
                    info!(
                        "Echoing message: {:?}, line size: {}, send {:?}",
                        String::from_utf8_lossy(line),
                        line.len(),
                        send,
                    );

                    // Add delay before sending response if configured
                    if options.response_delay > 0 {
                        info!("Delaying response for {} ms", options.response_delay);
                        sleep(Duration::from_millis(options.response_delay)).await;
                    }

                    // Send the line including newline
                    send.write_all(line)
                        .await
                        .map_err(|e| anyhow!("failed to send response: {}", e))?;

                    message_count += 1;
                    if message_count == options.reset_after_messages
                        && options.reset_after_messages > 0
                    {
                        info!("Resetting stream after {} messages", message_count);
                        send.reset(8u32.into())
                            .map_err(|e| anyhow!("failed to reset stream: {}", e))?;
                        sleep(Duration::from_millis(4000)).await;
                        return Ok(());
                    }
                    if message_count == options.finish_after_messages
                        && options.finish_after_messages > 0
                    {
                        info!("Finishing stream after {} messages", message_count);
                        send.finish()?;
                        sleep(Duration::from_millis(4000)).await;
                        return Ok(());
                    }

                    // Keep the remaining data
                    info!(
                        "Remaining buffer size: {}, buffer: {:?}",
                        rest.len(),
                        String::from_utf8_lossy(rest)
                    );
                    buffer = rest.to_vec();
                }
            }
            Err(e) => {
                return Err(anyhow!("failed reading request: {}", e));
            }
        }
    }

    Ok(())
}
