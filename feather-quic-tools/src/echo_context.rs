use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::{error, info, trace};

use feather_quic_core::prelude::*;

pub struct FeatherQuicEchoContext {
    file_path: String,
    reader: Option<BufReader<File>>,
    current_line: Option<String>,
    stream_handle: Option<QuicStreamHandle>,
}

impl FeatherQuicEchoContext {
    pub fn new(file_path: String) -> Result<Self> {
        let reader = BufReader::new(
            File::open(&file_path)
                .with_context(|| format!("Failed to open file: {}", file_path))?,
        );

        Ok(Self {
            file_path,
            reader: Some(reader),
            current_line: None,
            stream_handle: None,
        })
    }

    fn read_next_line(&mut self) -> Result<Option<String>> {
        if let Some(reader) = &mut self.reader {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                // EOF reached
                self.reader = None;
                return Ok(None);
            }
            Ok(Some(line.trim().to_string()))
        } else {
            Ok(None)
        }
    }

    fn send_line(&self, qconn: &mut QuicConnection, line: &str) -> Result<()> {
        if let Some(stream) = self.stream_handle {
            let buf = line.as_bytes();
            match qconn.stream_send(stream, buf) {
                Ok(sent_bytes) => {
                    trace!(
                        "Quic stream {:?} sent {} bytes successfully",
                        stream,
                        sent_bytes
                    );
                }
                Err(e) => match e {
                    QuicConnectionError::StreamNotExist(_) => {
                        error!("Stream does not exist");
                    }
                    QuicConnectionError::QuicStreamError(e) => {
                        if matches!(e, QuicStreamError::WouldBlock) {
                            qconn.set_stream_write_active(stream, true)?;
                        } else {
                            error!("Quic stream error: {:?}", e);
                        }
                    }
                    _ => panic!("Unknown error: {:?}", e),
                },
            }
        }
        Ok(())
    }

    fn verify_response(&mut self, response: &[u8]) -> Result<()> {
        if let Some(expected) = &self.current_line {
            let response_str = String::from_utf8_lossy(response);
            if response_str.trim() != expected {
                return Err(anyhow::anyhow!(
                    "Echo verification failed. Expected: '{}', Got: '{}'",
                    expected,
                    response_str.trim()
                ));
            }
            info!("Echo verification successful for line: '{}'", expected);
            self.current_line = None;
        }
        Ok(())
    }
}

impl QuicCallbacks for FeatherQuicEchoContext {
    fn close(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        info!("QUIC connection closed");
        Ok(())
    }

    fn connect_done(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        info!("QUIC connection established successfully");

        let new_stream = qconn.open_stream(true)?;
        self.stream_handle = Some(new_stream);

        // Read and send first line
        if let Some(line) = self.read_next_line()? {
            self.current_line = Some(line.clone());
            self.send_line(qconn, &line)?;
        }

        Ok(())
    }

    fn read_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()> {
        trace!("QUIC stream {:?} readable event received", stream_handle);

        // Read response data
        let recv_len = 1024;
        match qconn.stream_recv(stream_handle, recv_len) {
            Ok(recv_bytes) => {
                trace!(
                    "Quic stream {:?} received {} bytes successfully",
                    stream_handle,
                    recv_bytes.len()
                );

                // Verify the response
                self.verify_response(&recv_bytes)?;

                // Read and send next line if available
                if let Some(line) = self.read_next_line()? {
                    self.current_line = Some(line.clone());
                    self.send_line(qconn, &line)?;
                } else {
                    // No more lines to send, finish the stream
                    qconn.stream_finish(stream_handle)?;
                    qconn.stream_shutdown_read(stream_handle, 0x09)?;
                }
            }
            Err(e) => match e {
                QuicConnectionError::StreamNotExist(_) => {
                    error!("Stream does not exist");
                }
                QuicConnectionError::QuicStreamError(e) => {
                    if matches!(e, QuicStreamError::WouldBlock) {
                        qconn.set_stream_read_active(stream_handle, true)?;
                    } else {
                        error!("Quic stream error: {:?}", e);
                    }
                }
                _ => panic!("Unknown error: {:?}", e),
            },
        }

        Ok(())
    }

    fn write_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()> {
        trace!("QUIC stream {:?} writable event received", stream_handle);

        // If we have a current line that wasn't sent successfully, try sending it again
        if let Some(line) = &self.current_line {
            self.send_line(qconn, line)?;
        }

        Ok(())
    }
}
