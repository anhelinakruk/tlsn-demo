use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, FutureExt, future::LocalBoxFuture};
use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    ReadableStreamDefaultReader, WebTransportBidirectionalStream,
    WritableStreamDefaultWriter,
};

fn js_to_io(e: JsValue) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

enum ReadState {
    Idle,
    Reading(LocalBoxFuture<'static, Result<JsValue, JsValue>>),
    Buffered(Vec<u8>, usize),
    Closed,
}

enum WriteState {
    Idle,
    Writing(LocalBoxFuture<'static, Result<JsValue, JsValue>>),
}

enum CloseState {
    Open,
    Closing(LocalBoxFuture<'static, Result<JsValue, JsValue>>),
    Closed,
}

pub struct WebTransportIo {
    reader: ReadableStreamDefaultReader,
    writer: WritableStreamDefaultWriter,
    read_state: ReadState,
    write_state: WriteState,
    close_state: CloseState,
}

// Safety: this type must never be accessed from multiple threads; it's only `Send` to satisfy
// downstream trait bounds while remaining confined to a single WASM worker.
unsafe impl Send for WebTransportIo {}

impl WebTransportIo {
    pub fn from_bidi(stream: WebTransportBidirectionalStream) -> Result<Self, JsValue> {
        let reader = stream
            .readable()
            .get_reader()
            .dyn_into::<ReadableStreamDefaultReader>()?;
        let writer = stream.writable().get_writer()?;
        Ok(Self {
            reader,
            writer,
            read_state: ReadState::Idle,
            write_state: WriteState::Idle,
            close_state: CloseState::Open,
        })
    }
}

impl AsyncRead for WebTransportIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.read_state {
                ReadState::Closed => return Poll::Ready(Ok(0)),
                ReadState::Buffered(data, offset) => {
                    let remaining = data.len() - *offset;
                    let n = remaining.min(buf.len());
                    buf[..n].copy_from_slice(&data[*offset..*offset + n]);
                    *offset += n;
                    if *offset == data.len() {
                        self.read_state = ReadState::Idle;
                    }
                    return Poll::Ready(Ok(n));
                }
                ReadState::Idle => {
                    let promise = self.reader.read();
                    self.read_state =
                        ReadState::Reading(JsFuture::from(promise).boxed_local());
                }
                ReadState::Reading(fut) => {
                    let chunk = match fut.poll_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(js_to_io(e))),
                        Poll::Ready(Ok(v)) => v,
                    };

                    let done = js_sys::Reflect::get(&chunk, &"done".into())
                        .map(|v| v.as_bool().unwrap_or(false))
                        .unwrap_or(false);

                    if done {
                        self.read_state = ReadState::Closed;
                        return Poll::Ready(Ok(0));
                    }

                    let value = js_sys::Reflect::get(&chunk, &"value".into())
                        .map_err(js_to_io)?;
                    let array = Uint8Array::new(&value);
                    let data = array.to_vec();

                    if data.is_empty() {
                        self.read_state = ReadState::Idle;
                        continue;
                    }

                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        self.read_state = ReadState::Buffered(data, n);
                    } else {
                        self.read_state = ReadState::Idle;
                    }
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }
}

impl AsyncWrite for WebTransportIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.write_state {
                WriteState::Writing(fut) => match fut.poll_unpin(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(js_to_io(e))),
                    Poll::Ready(Ok(_)) => {
                        self.write_state = WriteState::Idle;
                    }
                },
                WriteState::Idle => {
                    let array = Uint8Array::from(buf);
                    let promise = self.writer.write_with_chunk(&array);
                    self.write_state =
                        WriteState::Writing(JsFuture::from(promise).boxed_local());
                    let n = buf.len();
                    // Drive the write to completion so backpressure is respected,
                    // but return the count immediately (the future will finish next poll).
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.close_state {
                CloseState::Closed => return Poll::Ready(Ok(())),
                CloseState::Closing(fut) => match fut.poll_unpin(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(js_to_io(e))),
                    Poll::Ready(Ok(_)) => {
                        self.close_state = CloseState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                },
                CloseState::Open => {
                    let promise = self.writer.close();
                    self.close_state =
                        CloseState::Closing(JsFuture::from(promise).boxed_local());
                }
            }
        }
    }
}
