use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::{error, info, trace, warn};

use feather_quic_core::prelude::*;

struct QuicStreamContext {
    reader: BufReader<File>,
    current_line: String,
    unsent_data: Option<(Vec<u8>, usize)>, // (data, offset)
    whole_message: Vec<u8>,
}

pub struct FeatherQuicEchoContext {
    file_path: String,
    stream_contexts: HashMap<QuicStreamHandle, QuicStreamContext>,
    stream_handles: Vec<QuicStreamHandle>,
    num_streams: u64,
}

impl FeatherQuicEchoContext {
    pub fn new(file_path: String, num_streams: u64) -> Result<Self> {
        Ok(Self {
            file_path,
            stream_contexts: HashMap::new(),
            stream_handles: Vec::new(),
            num_streams,
        })
    }

    fn read_next_line(&mut self, stream_handle: QuicStreamHandle) -> Result<Option<String>> {
        if let Some(context) = self.stream_contexts.get_mut(&stream_handle) {
            let mut line = String::new();
            if context.reader.read_line(&mut line)? == 0 {
                // EOF reached
                return Ok(None);
            }
            Ok(Some(line))
        } else {
            Ok(None)
        }
    }

    fn read_and_verify_response(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()> {
        loop {
            let recv_len = 1024;
            match qconn.stream_recv(stream_handle, recv_len) {
                Ok(recv_bytes) => {
                    let context = match self.stream_contexts.get_mut(&stream_handle) {
                        Some(ctx) => ctx,
                        None => return Ok(()),
                    };

                    trace!(
                        "Quic stream {:?} received {} bytes successfully, whole message length: {}",
                        stream_handle,
                        recv_bytes.len(),
                        context.whole_message.len()
                    );

                    context.whole_message.extend(recv_bytes);

                    let response_str = String::from_utf8_lossy(&context.whole_message);
                    if response_str.contains('\n') {
                        self.verify_response(stream_handle)?;

                        let next_line = self.read_next_line(stream_handle)?;
                        if let Some(line) = next_line {
                            if let Some(context) = self.stream_contexts.get_mut(&stream_handle) {
                                context.current_line = line.clone();
                                self.send_line(qconn, stream_handle, &line)?;
                            }
                        } else {
                            qconn.stream_finish(stream_handle)?;
                            qconn.stream_shutdown_read(stream_handle, 0x09)?;
                            self.stream_handles.remove(
                                self.stream_handles
                                    .iter()
                                    .position(|h| *h == stream_handle)
                                    .unwrap(),
                            );
                            if self.stream_handles.is_empty() {
                                info!("All streams finished, exiting");
                                qconn.close(2077, Some("mission completed".to_string()))?;
                            } else {
                                trace!("Stream {} was closed", stream_handle);
                            }
                        }
                        return Ok(());
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
                            warn!("Quic stream error: {:?}", e);
                            qconn.stream_finish(stream_handle)?;
                            self.stream_handles.remove(
                                self.stream_handles
                                    .iter()
                                    .position(|h| *h == stream_handle)
                                    .unwrap(),
                            );
                            if self.stream_handles.is_empty() {
                                info!("All streams finished, due to early termination");
                                qconn.close(
                                    2077,
                                    Some("stream was finished or reset".to_string()),
                                )?;
                            } else {
                                trace!("Stream {} was closed", stream_handle);
                            }
                        }
                        break;
                    }
                    _ => panic!("Unknown error: {:?}", e),
                },
            }
        }
        Ok(())
    }

    fn send_line(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
        line: &str,
    ) -> Result<()> {
        let buf = line.as_bytes();
        match qconn.stream_send(stream_handle, buf) {
            Ok(sent_bytes) => {
                if sent_bytes < buf.len() {
                    trace!(
                        "Quic stream {:?} sent {} bytes, {} bytes remaining",
                        stream_handle,
                        sent_bytes,
                        buf.len() - sent_bytes
                    );
                    // Store the remaining data for next send attempt
                    if let Some(context) = self.stream_contexts.get_mut(&stream_handle) {
                        context.unsent_data = Some((buf[sent_bytes..].to_vec(), sent_bytes));
                    }
                    qconn.set_stream_write_active(stream_handle, true)?;
                } else {
                    // Successfully sent all data, trigger stream reading
                    self.read_and_verify_response(qconn, stream_handle)?;
                }
            }
            Err(e) => match e {
                QuicConnectionError::StreamNotExist(_) => {
                    error!("Stream does not exist");
                }
                QuicConnectionError::QuicStreamError(e) => {
                    if matches!(e, QuicStreamError::WouldBlock) {
                        // Store the entire data for next send attempt
                        if let Some(context) = self.stream_contexts.get_mut(&stream_handle) {
                            context.unsent_data = Some((buf.to_vec(), 0));
                        }
                        trace!("QUIC stream {:?} was sent blocked", stream_handle);
                        qconn.set_stream_write_active(stream_handle, true)?;

                        // Just for the intergration test
                        qconn.close(2077, Some("should not be would blocked".to_string()))?;
                    } else {
                        error!("Quic stream error: {:?}", e);
                    }
                }
                QuicConnectionError::ConnectionMaxDataLimitations(limit) => {
                    trace!(
                        "QUIC stream {:?} was sent blocked, limit: {}",
                        stream_handle,
                        limit
                    );
                    qconn.set_stream_write_active(stream_handle, true)?;
                    // Just for the intergration test
                    if limit == 0 {
                        qconn.close(
                            2077,
                            Some("Peer doesn't have any connection data size".to_string()),
                        )?;
                    }
                }
                _ => panic!("Unknown error: {:?}", e),
            },
        }
        Ok(())
    }

    fn verify_response(&mut self, stream_handle: QuicStreamHandle) -> Result<()> {
        if let Some(context) = self.stream_contexts.get_mut(&stream_handle) {
            let response_str = String::from_utf8_lossy(&context.whole_message);
            if response_str != context.current_line {
                return Err(anyhow::anyhow!(
                    "Echo verification failed for stream {:?}. Expected: {} bytes '{}', Got: {} bytes '{}'",
                    stream_handle,
                    context.current_line.len(),
                    context.current_line,
                    response_str.len(),
                    response_str
                ));
            }
            info!(
                "Echo verification successful for stream {:?} line: '{}'",
                stream_handle, context.current_line
            );
            context.whole_message.clear();
        }
        Ok(())
    }
}

impl QuicCallbacks for FeatherQuicEchoContext {
    fn close(
        &mut self,
        _qconn: &mut QuicConnection,
        error_code: Option<u64>,
        reason: Option<String>,
    ) -> Result<()> {
        info!(
            "QUIC connection close callback, error_code {:?}, reason {:?}",
            error_code, reason
        );
        Ok(())
    }

    fn connect_done(
        &mut self,
        qconn: &mut QuicConnection,
        result: QuicConnectResult,
    ) -> Result<()> {
        match result {
            QuicConnectResult::Success => {
                info!("QUIC connection established successfully");
            }
            QuicConnectResult::Timeout(duration) => {
                info!(
                    "QUIC connection establishment timed out after {}ms",
                    duration
                );
                return Ok(());
            }
            QuicConnectResult::Failed(reason) => {
                info!("QUIC connection establishment failed, due to {}", reason);
                return Ok(());
            }
        }

        // Create multiple streams
        for _ in 0..self.num_streams {
            let new_stream = match qconn.open_stream(true) {
                Err(QuicConnectionError::StreamLimitations(s, l)) => {
                    warn!(
                        "Can not open {} stream, due to streams limitation {:?}",
                        s, l
                    );
                    qconn.close(2077, Some("can not open stream".to_string()))?;
                    return Ok(());
                }
                Err(e) => panic!("Can not open stream due to {:?}", e),
                Ok(s) => s,
            };
            self.stream_handles.push(new_stream);

            // Create a new file reader for each stream
            let mut reader = BufReader::new(
                File::open(&self.file_path)
                    .with_context(|| format!("Failed to open file: {}", self.file_path))?,
            );

            // Read and send first line for each stream
            let mut line = String::new();
            if reader.read_line(&mut line)? > 0 {
                self.stream_contexts.insert(
                    new_stream,
                    QuicStreamContext {
                        reader,
                        current_line: line.clone(),
                        unsent_data: None,
                        whole_message: Vec::new(),
                    },
                );
                self.send_line(qconn, new_stream, &line)?;
            }
        }

        Ok(())
    }

    fn read_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()> {
        trace!("QUIC stream {:?} readable event received", stream_handle);
        self.read_and_verify_response(qconn, stream_handle)
    }

    fn write_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()> {
        trace!("QUIC stream {:?} writable event received", stream_handle);

        // Try to send any unsent data first
        let (data, offset) = if let Some(context) = self.stream_contexts.get(&stream_handle) {
            if let Some((data, offset)) = context.unsent_data.as_ref() {
                (data.clone(), *offset)
            } else {
                return Ok(());
            }
        } else {
            return Ok(());
        };

        match qconn.stream_send(stream_handle, &data[offset..]) {
            Ok(sent_bytes) => {
                let new_offset = offset + sent_bytes;
                if new_offset < data.len() {
                    // Still have data to send
                    if let Some(context) = self.stream_contexts.get_mut(&stream_handle) {
                        context.unsent_data = Some((data, new_offset));
                    }
                    qconn.set_stream_write_active(stream_handle, true)?;
                    return Ok(());
                }
            }
            Err(e) => match e {
                QuicConnectionError::QuicStreamError(QuicStreamError::WouldBlock) => {
                    trace!("QUIC stream {:?} was sent blocked", stream_handle);
                    // Store the data back for next attempt
                    if let Some(context) = self.stream_contexts.get_mut(&stream_handle) {
                        context.unsent_data = Some((data, offset));
                    }
                    qconn.set_stream_write_active(stream_handle, true)?;

                    // Just for the intergration test
                    qconn.close(2077, Some("should not be would blocked".to_string()))?;
                    return Ok(());
                }
                QuicConnectionError::ConnectionMaxDataLimitations(limit) => {
                    trace!(
                        "QUIC stream {:?} was sent blocked, limit: {}",
                        stream_handle,
                        limit
                    );

                    qconn.set_stream_write_active(stream_handle, true)?;

                    // Just for the intergration test
                    if limit == 0 {
                        qconn.close(
                            2077,
                            Some("Peer doesn't have any connection data size".to_string()),
                        )?;
                    }
                    return Ok(());
                }
                _ => {
                    error!("Failed to send remaining data: {:?}", e);
                }
            },
        }

        Ok(())
    }
}
