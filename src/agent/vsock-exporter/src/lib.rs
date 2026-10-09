// Copyright (c) 2020-2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// The VSOCK Exporter sends trace spans "out" to the forwarder running on the
// host (which then forwards them on to a trace collector). The data is sent
// via a VSOCK socket that the forwarder process is listening on. To allow the
// forwarder to know how much data to each for each trace span the simplest
// protocol is employed which uses a header packet and the payload (trace
// span) data. The header packet is a simple count of the number of bytes in the
// payload, which allows the forwarder to know how many bytes it must read to
// consume the trace span. The payload is a serialised version of the trace span.

#![allow(unknown_lints)]

use async_trait::async_trait;
use byteorder::{ByteOrder, NetworkEndian};
use opentelemetry::sdk::export::trace::{ExportResult, SpanData, SpanExporter};
use opentelemetry::sdk::export::ExportError;
use slog::{error, o, Logger};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{sleep_until, timeout, Instant};
use tokio_vsock::VsockStream;

const ANY_CID: &str = "any";

// Must match the value of the variable of the same name in the trace forwarder.
const HEADER_SIZE_BYTES: u64 = std::mem::size_of::<u64>() as u64;

// By default, the VSOCK exporter should talk "out" to the host where the
// forwarder is running.
const DEFAULT_CID: u32 = libc::VMADDR_CID_HOST;

// The VSOCK port the forwarders listens on by default
const DEFAULT_PORT: u32 = 10240;

// Bound the complete export, including connection setup, writes and backoff,
// by the BatchSpanProcessor's default export timeout. Its shorter deadlines
// may still cancel us. The processor owns the queue; we retain only its batch.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(30);
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct Exporter {
    port: u32,
    cid: u32,
    conn: Option<Arc<Mutex<VsockStream>>>,
    retry_delay: Duration,
    retry_at: Option<Instant>,
    logger: Logger,
}

impl Exporter {
    /// Create a new exporter builder.
    pub fn builder() -> Builder {
        Builder::default()
    }

    async fn export_with_retry(&mut self, batch: &[SpanData]) -> ExportResult {
        // Keep ownership inside this future so any error or cancellation drops
        // an incomplete stream. Only a fully written batch restores the cache.
        let mut conn = self.conn.take();
        loop {
            if let Some(retry_at) = self.retry_at {
                sleep_until(retry_at).await;
            }

            let maximum_ms = self.retry_delay.as_millis() as u64;
            let delay = Duration::from_millis(rand::random_range(maximum_ms * 4 / 5..=maximum_ms));
            self.retry_delay = (self.retry_delay * 2).min(MAX_RETRY_DELAY);
            // Arm before awaiting so cancellation does not reset the backoff.
            // Preserve this state across batches that exhaust their budget.
            self.retry_at = Some(Instant::now() + delay);

            let result = async {
                if conn.is_none() {
                    let stream = connect_vsock(self.cid, self.port).await?;
                    conn = Some(Arc::new(Mutex::new(stream)));
                }
                handle_batch(conn.as_ref().unwrap().clone(), batch).await
            }
            .await;

            match result {
                Ok(()) => {
                    self.conn = conn;
                    self.retry_delay = INITIAL_RETRY_DELAY;
                    self.retry_at = None;
                    return Ok(());
                }
                Err(err @ Error::SerialisationError(_)) => return Err(err.into()),
                Err(err) => {
                    error!(self.logger, "trace export failed; retrying"; "error" => err.to_string(), "retry_ms" => delay.as_millis());
                    conn = None;
                    self.retry_at = Some(Instant::now() + delay);
                }
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("serialisation error: {0}")]
    SerialisationError(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
}

impl ExportError for Error {
    fn exporter_name(&self) -> &'static str {
        "vsock-exporter"
    }
}

// Send a trace span to the forwarder running on the host.
async fn write_span(writer: Arc<Mutex<VsockStream>>, span: &SpanData) -> Result<(), Error> {
    let mut writer = writer.lock().await;

    let encoded_payload: Vec<u8> = serde_json::to_vec(span)?;
    let payload_len: u64 = encoded_payload.len() as u64;

    let mut payload_len_as_bytes: [u8; HEADER_SIZE_BYTES as usize] =
        [0; HEADER_SIZE_BYTES as usize];

    // Encode the header
    NetworkEndian::write_u64(&mut payload_len_as_bytes, payload_len);

    // Send the header
    writer.write_all(&payload_len_as_bytes).await?;

    writer.write_all(&encoded_payload).await?;
    Ok(())
}

async fn handle_batch(writer: Arc<Mutex<VsockStream>>, batch: &[SpanData]) -> Result<(), Error> {
    for span_data in batch {
        write_span(writer.clone(), span_data).await?;
    }

    Ok(())
}

#[async_trait]
impl SpanExporter for Exporter {
    async fn export(&mut self, batch: Vec<SpanData>) -> ExportResult {
        // A retry can duplicate spans already written before a failure: the
        // wire protocol has no acknowledgements. Never replay a partial frame
        // on the same stream; retry the supplied batch on a new connection.
        timeout(EXPORT_TIMEOUT, self.export_with_retry(&batch))
            .await
            .map_err(|_| {
                Error::IOError(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "VSOCK export exceeded its 30 second retry budget",
                ))
            })?
    }

    fn shutdown(&mut self) {
        self.conn.take();
    }
}

#[derive(Debug)]
pub struct Builder {
    port: u32,
    cid: u32,
    logger: Logger,
}

impl Default for Builder {
    fn default() -> Self {
        let logger = Logger::root(slog::Discard, o!());

        Builder {
            cid: DEFAULT_CID,
            port: DEFAULT_PORT,
            logger,
        }
    }
}

impl Builder {
    pub fn with_cid(self, cid: u32) -> Self {
        Builder { cid, ..self }
    }

    pub fn with_port(self, port: u32) -> Self {
        Builder { port, ..self }
    }

    pub fn with_logger(self, logger: &Logger) -> Self {
        Builder {
            logger: logger.new(o!()),
            ..self
        }
    }

    pub fn init(self) -> Exporter {
        let Builder { port, cid, logger } = self;

        let cid_str: String = if self.cid == libc::VMADDR_CID_ANY {
            ANY_CID.to_string()
        } else {
            format!("{}", self.cid)
        };

        Exporter {
            port,
            cid,
            conn: None,
            retry_delay: INITIAL_RETRY_DELAY,
            retry_at: None,
            logger: logger.new(o!("cid" => cid_str, "port" => port)),
        }
    }
}

async fn connect_vsock(cid: u32, port: u32) -> Result<VsockStream, Error> {
    match VsockStream::connect(cid, port).await {
        Ok(conn) => Ok(conn),
        Err(e) => Err(Error::ConnectionError(e.to_string())),
    }
}
