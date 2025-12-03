use std::io;
use std::os::fd::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{error, warn};

use sb_platform::tun::{TunDevice, TunError};

pub struct TunDeviceDriver {
    device: AsyncFd<Box<dyn TunDevice>>,
    rx_sender: mpsc::Sender<Vec<u8>>,
    tx_receiver: mpsc::Receiver<Vec<u8>>,
    mtu: usize,
}

impl TunDeviceDriver {
    pub fn new(
        device: Box<dyn TunDevice>,
        rx_sender: mpsc::Sender<Vec<u8>>,
        tx_receiver: mpsc::Receiver<Vec<u8>>,
        mtu: usize,
    ) -> io::Result<Self> {
        // Set non-blocking mode
        let fd = device.as_raw_fd();
        set_nonblocking(fd)?;

        let device = AsyncFd::new(device)?;

        Ok(Self {
            device,
            rx_sender,
            tx_receiver,
            mtu,
        })
    }

    pub async fn run(mut self) {
        let mut buf = vec![0u8; self.mtu + 14]; // MTU + Ethernet header safety margin

        loop {
            tokio::select! {
                // Read from TUN device
                guard = self.device.readable() => {
                    match guard {
                        Ok(mut guard) => {
                            match guard.try_io(|inner| {
                                inner.get_mut().read(&mut buf).map_err(|e| {
                                    match e {
                                        TunError::IoError(io_err) => io_err,
                                        _ => io::Error::new(io::ErrorKind::Other, e.to_string()),
                                    }
                                })
                            }) {
                                Ok(Ok(n)) => {
                                    if n > 0 {
                                        let packet = buf[..n].to_vec();
                                        if let Err(_) = self.rx_sender.send(packet).await {
                                            warn!("TunStack RX channel closed");
                                            break;
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!("Failed to read from TUN device: {}", e);
                                    break;
                                }
                                Err(_would_block) => continue,
                            }
                        }
                        Err(e) => {
                            error!("AsyncFd readable error: {}", e);
                            break;
                        }
                    }
                }

                // Write to TUN device
                Some(packet) = self.tx_receiver.recv() => {
                    let mut pos = 0;
                    while pos < packet.len() {
                        // Try to write
                        // Note: inner.write returns Result<usize, TunError>
                        // We need to handle WouldBlock manually if TunError wraps it
                        let res = self.device.get_mut().write(&packet[pos..]);
                        match res {
                            Ok(n) => {
                                pos += n;
                            }
                            Err(TunError::IoError(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                                // Wait for writable
                                match self.device.writable().await {
                                    Ok(mut guard) => {
                                        // Clear readiness so we don't spin?
                                        // AsyncFd readiness is edge-triggered usually.
                                        // But we need to try_io to clear it properly?
                                        // Actually guard.clear_ready() is needed if we don't use try_io.
                                        // But here we just wait and retry.
                                        guard.clear_ready();
                                        continue;
                                    }
                                    Err(e) => {
                                        error!("AsyncFd writable error: {}", e);
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to write to TUN device: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
