//! A device's stdout, stderr and stdin as wasmtime-wasi streams.
//!
//! The capture itself (bytes, line journalling with virtual timestamps) is runtime-agnostic and
//! lives in `wasmnet-core` ([`OutputCapture`]). This is only the wasmtime-wasi side: the p2
//! `OutputStream` and the p3 `AsyncWrite` that feed it. Writes reach it inside the device's event
//! loop (p2 `blocking-write-and-flush` or the p3 stdout stream's host task), so the stamps are
//! as deterministic as everything else.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasmnet_core::{CAPTURE_LIMIT, InputQueue, OutputCapture};
use wasmtime_wasi::cli::{IsTerminal, StdinStream, StdoutStream};
use wasmtime_wasi::p2::{InputStream, OutputStream, Pollable, StreamError};

/// One captured output stream. Cloning gives another handle to the same buffer.
#[derive(Clone)]
pub(crate) struct OutputPipe(pub(crate) OutputCapture);

impl IsTerminal for OutputPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for OutputPipe {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }

    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

#[wasmtime_wasi::async_trait]
impl OutputStream for OutputPipe {
    fn write(&mut self, bytes: Bytes) -> Result<(), StreamError> {
        if self.0.append(&bytes) < bytes.len() {
            return Err(StreamError::Trap(wasmtime::format_err!(
                "write beyond the {CAPTURE_LIMIT}-byte capture limit"
            )));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamError> {
        Ok(())
    }

    fn check_write(&mut self) -> Result<usize, StreamError> {
        match self.0.remaining() {
            0 => Err(StreamError::Closed),
            room => Ok(room),
        }
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for OutputPipe {
    async fn ready(&mut self) {}
}

/// A device's stdin: the bytes of its `Op::Stdin` operator events.
///
/// - p3 (`read-via-stream`, a console): open for the device's life. A read with
///   nothing queued is pending until the next write wakes it; there is no end of file.
/// - p2 (`std::io::stdin()`): what is queued, else end of stream at once, so a program that reads fd 0 without a console never waits.
#[derive(Clone)]
pub(crate) struct InputPipe(pub(crate) InputQueue);

impl IsTerminal for InputPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdinStream for InputPipe {
    fn async_stream(&self) -> Box<dyn AsyncRead + Send + Sync> {
        Box::new(self.clone())
    }

    fn p2_stream(&self) -> Box<dyn InputStream> {
        Box::new(self.clone())
    }
}

impl AsyncRead for InputPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.0.poll_take(cx, buf.remaining()) {
            Poll::Ready(bytes) => {
                buf.put_slice(&bytes);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[wasmtime_wasi::async_trait]
impl InputStream for InputPipe {
    fn read(&mut self, size: usize) -> Result<Bytes, StreamError> {
        let bytes = self.0.take(size);
        if bytes.is_empty() && size > 0 {
            return Err(StreamError::Closed);
        }
        Ok(Bytes::from(bytes))
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for InputPipe {
    /// Always ready: a p2 read answers now (bytes or end of stream).
    async fn ready(&mut self) {}
}

impl AsyncWrite for OutputPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(self.0.append(buf)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
