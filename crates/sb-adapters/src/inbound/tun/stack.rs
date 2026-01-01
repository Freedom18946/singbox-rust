//! Userspace network stack wrapper using smoltcp.
//!
//! This module provides a high-level interface to the smoltcp stack,
//! bridging between the TUN interface (raw bytes) and Tokio streams (TCP/UDP).
//!
//! NOTE: Skeleton/WIP code - warnings suppressed.
#![allow(unused, dead_code, unreachable_pub)]

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::{Duration, Instant as SmolInstant};
use smoltcp::wire::{IpAddress, IpCidr, IpProtocol};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, error, trace, warn};

/// A virtual device that reads/writes to the TUN interface via channels.
pub struct VirtualTunDevice {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    mtu: usize,
    rx_buffer: Option<Vec<u8>>,
}

impl VirtualTunDevice {
    pub fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>, mtu: usize) -> Self {
        Self {
            rx,
            tx,
            mtu,
            rx_buffer: None,
        }
    }

    /// Load a packet into the device's RX buffer (called by the poll loop)
    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.rx_buffer = Some(packet);
    }
}

impl Device for VirtualTunDevice {
    type RxToken<'a> = VecRxToken;
    type TxToken<'a> = ChannelTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.rx_buffer.take() {
            Some((
                VecRxToken { buffer },
                ChannelTxToken {
                    tx: self.tx.clone(),
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken {
            tx: self.tx.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct VecRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VecRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct ChannelTxToken {
    tx: mpsc::Sender<Vec<u8>>,
}

impl TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        // Ignore send errors (channel full/closed)
        let _ = self.tx.try_send(buffer);
        result
    }
}

/// The userspace network stack.
pub struct TunStack {
    interface: Interface,
    socket_set: SocketSet<'static>,
    device: VirtualTunDevice,
}

impl TunStack {
    pub fn new(mtu: usize, tx: mpsc::Sender<Vec<u8>>) -> Self {
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();

        // Create a dummy channel for the device initialization
        // The actual RX channel will be managed by the caller injecting packets
        let (_, rx) = mpsc::channel(1);

        let device = VirtualTunDevice::new(rx, tx, mtu);

        let interface = Interface::new(
            config,
            &mut VirtualTunDevice::new(mpsc::channel(1).1, mpsc::channel(1).0, mtu),
            SmolInstant::now(),
        );
        let socket_set = SocketSet::new(vec![]);

        // Re-create proper device/interface structure
        // Note: smoltcp Interface takes ownership of the device in some versions,
        // or just uses it during poll.
        // In current smoltcp, Interface holds state, Device is passed to poll.
        // So we just need to keep the device around.

        Self {
            interface,
            socket_set,
            device,
        }
    }

    /// Poll the stack: process ingress packets and handle timers.
    pub fn poll(&mut self, ingress_packet: Option<Vec<u8>>) {
        let timestamp = SmolInstant::now();

        if let Some(packet) = ingress_packet {
            self.device.inject_packet(packet);
        }

        // smoltcp poll returns bool indicating if any work was done
        let _ = self
            .interface
            .poll(timestamp, &mut self.device, &mut self.socket_set);
    }

    /// Create a new TCP socket listening on the specified address
    pub fn listen_tcp(&mut self, addr: SocketAddr) -> SocketHandle {
        let rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

        if let Err(e) = socket.listen(addr) {
            error!("Failed to listen on {}: {}", addr, e);
        }

        self.socket_set.add(socket)
    }

    /// Check for new TCP connections and return the socket handle if any
    pub fn accept_tcp(&mut self) -> Option<SocketHandle> {
        // This is a simplification. In a real implementation, we'd iterate over sockets
        // and check their state. For now, we assume the caller manages handles.
        None
    }

    /// Create a new TCP socket and initiate connection to the specified remote address.
    /// Returns the socket handle which can be polled for connection completion.
    pub fn connect_tcp(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> std::io::Result<SocketHandle> {
        let rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);

        let handle = self.socket_set.add(socket);

        let local_endpoint = smoltcp::wire::IpEndpoint {
            addr: match local_addr.ip() {
                IpAddr::V4(v4) => IpAddress::v4(v4.octets()[0], v4.octets()[1], v4.octets()[2], v4.octets()[3]),
                IpAddr::V6(v6) => IpAddress::v6(
                    v6.segments()[0], v6.segments()[1], v6.segments()[2], v6.segments()[3],
                    v6.segments()[4], v6.segments()[5], v6.segments()[6], v6.segments()[7],
                ),
            },
            port: local_addr.port(),
        };

        let remote_endpoint = smoltcp::wire::IpEndpoint {
            addr: match remote_addr.ip() {
                IpAddr::V4(v4) => IpAddress::v4(v4.octets()[0], v4.octets()[1], v4.octets()[2], v4.octets()[3]),
                IpAddr::V6(v6) => IpAddress::v6(
                    v6.segments()[0], v6.segments()[1], v6.segments()[2], v6.segments()[3],
                    v6.segments()[4], v6.segments()[5], v6.segments()[6], v6.segments()[7],
                ),
            },
            port: remote_addr.port(),
        };

        let socket: &mut tcp::Socket<'_> = self.socket_set.get_mut(handle);
        socket.connect(self.interface.context(), remote_endpoint, local_endpoint)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("smoltcp connect: {e:?}")))?;

        debug!("Initiated TCP connection from {} to {}", local_addr, remote_addr);
        Ok(handle)
    }

    /// Check if a TCP socket has completed its connection.
    pub fn is_tcp_connected(&mut self, handle: SocketHandle) -> bool {
        let socket: &tcp::Socket<'_> = self.socket_set.get(handle);
        socket.is_active() && socket.may_send()
    }

    /// Check if a TCP socket can send data.
    pub fn can_send(&mut self, handle: SocketHandle) -> bool {
        let socket: &tcp::Socket<'_> = self.socket_set.get(handle);
        socket.can_send()
    }

    /// Send data on a TCP socket.
    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> std::io::Result<usize> {
        let socket: &mut tcp::Socket<'_> = self.socket_set.get_mut(handle);
        socket.send_slice(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("tcp send: {e:?}")))
    }

    /// Receive data from a TCP socket.
    pub fn tcp_recv(&mut self, handle: SocketHandle, buf: &mut [u8]) -> std::io::Result<usize> {
        let socket: &mut tcp::Socket<'_> = self.socket_set.get_mut(handle);
        socket.recv_slice(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("tcp recv: {e:?}")))
    }

    pub fn get_socket_mut<T: smoltcp::socket::AnySocket<'static>>(
        &mut self,
        handle: SocketHandle,
    ) -> &mut T {
        self.socket_set.get_mut(handle)
    }

    pub fn remove_socket(&mut self, handle: SocketHandle) {
        self.socket_set.remove(handle);
    }
}
