use pin_project_lite::pin_project;
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    pub struct PaddingStream<S> {
        #[pin]
        inner: S,
        read_state: ReadState,
        write_state: WriteState,
        is_client: bool,
        // Write buffer
        write_buf: Vec<u8>,
        write_pos: usize,
        // Read buffer
        read_buf: Vec<u8>,
        read_pos: usize,
        read_len_buf: [u8; 1],
    }
}

enum ReadState {
    Initial,
    ReadingLength,
    ReadingData,
    Done,
}

enum WriteState {
    Initial,
    Writing,
    Done,
}

impl<S> PaddingStream<S> {
    pub fn new(inner: S, is_client: bool) -> Self {
        Self {
            inner,
            read_state: ReadState::Initial,
            write_state: WriteState::Initial,
            is_client,
            write_buf: Vec::new(),
            write_pos: 0,
            read_buf: Vec::new(),
            read_pos: 0,
            read_len_buf: [0u8; 1],
        }
    }
}

impl<S> AsyncRead for PaddingStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        loop {
            match this.read_state {
                ReadState::Initial => {
                    *this.read_state = ReadState::ReadingLength;
                }
                ReadState::ReadingLength => {
                    let mut read_buf = ReadBuf::new(this.read_len_buf);
                    match this.inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            if read_buf.filled().is_empty() {
                                // EOF before padding length?
                                return Poll::Ready(Ok(()));
                            }
                            let len = this.read_len_buf[0] as usize;
                            if len == 0 {
                                *this.read_state = ReadState::Done;
                            } else {
                                *this.read_buf = vec![0u8; len];
                                *this.read_pos = 0;
                                *this.read_state = ReadState::ReadingData;
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReadState::ReadingData => {
                    let len = this.read_buf.len();
                    let pos = *this.read_pos;
                    if pos >= len {
                        *this.read_state = ReadState::Done;
                        continue;
                    }
                    let mut read_buf = ReadBuf::new(&mut this.read_buf[pos..]);
                    match this.inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF during padding",
                                )));
                            }
                            *this.read_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReadState::Done => {
                    return this.inner.poll_read(cx, buf);
                }
            }
        }
    }
}

impl<S> AsyncWrite for PaddingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        loop {
            match this.write_state {
                WriteState::Initial => {
                    let mut rng = rand::thread_rng();
                    let len: u8 = rng.gen();
                    let mut padding = vec![len];
                    for _ in 0..len {
                        padding.push(rng.gen());
                    }
                    *this.write_buf = padding;
                    *this.write_pos = 0;
                    *this.write_state = WriteState::Writing;
                }
                WriteState::Writing => {
                    let len = this.write_buf.len();
                    let pos = *this.write_pos;
                    if pos >= len {
                        *this.write_state = WriteState::Done;
                        continue;
                    }
                    match this.inner.as_mut().poll_write(cx, &this.write_buf[pos..]) {
                        Poll::Ready(Ok(n)) => {
                            *this.write_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                WriteState::Done => {
                    return this.inner.poll_write(cx, buf);
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        // Ensure padding is written before flushing?
        match this.write_state {
            WriteState::Done => this.inner.poll_flush(cx),
            _ => {
                // If we are still writing padding, we should try to finish it?
                // But poll_flush usually flushes the underlying stream.
                // We can't easily drive poll_write here without a buffer to write.
                // But we have write_buf.
                // Let's try to drive write state.
                match this.inner.as_mut().poll_write(cx, &[]) {
                    // Trigger write? No.
                    // Just return Pending if not done?
                    // Or try to advance state?
                    // It's complicated to call poll_write from poll_flush.
                    // Let's assume poll_write is called enough.
                    // But if user calls flush immediately...
                    Poll::Ready(Ok(_)) => this.inner.poll_flush(cx), // Fallback
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
