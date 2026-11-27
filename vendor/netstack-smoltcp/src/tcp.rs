use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use futures::Stream;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv6Address, TcpPacket},
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{
            error::TrySendError, unbounded_channel, Receiver, Sender, UnboundedReceiver,
            UnboundedSender,
        },
        Notify,
    },
};
use tracing::{error, trace};

use crate::{
    device::VirtualDevice,
    packet::{AnyIpPktFrame, IpPacket},
    Runner,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
}

struct TcpSocketCreation {
    control: SharedControl,
    socket: TcpSocket<'static>,
    key: FlowKey,
}

type SharedNotify = Arc<Notify>;
type SharedControl = Arc<SpinMutex<TcpSocketControl>>;
/// (client, destination) of one TCP connection.
type FlowKey = (SocketAddr, SocketAddr);

/// A handshake that has not reached ESTABLISHED within this time is abandoned (the client gave
/// up, or its SYN was lost before reaching the socket). Without it a socket that never sees its
/// SYN would sit in LISTEN, holding its buffers, forever; Linux gives up on a SYN-ACK after ~63 s.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default for [`crate::StackBuilder::tcp_max_sockets`].
pub(crate) const DEFAULT_MAX_SOCKETS: usize = 1024;

/// Bookkeeping shared by the packet handler (which creates sockets) and the socket poller
/// (which retires them). Both run inside the same runner future, never concurrently.
#[derive(Default)]
struct SocketRegistry {
    /// Flows whose socket still waits for its handshake to complete. A retransmitted SYN for one
    /// of these is passed to the existing socket instead of creating a duplicate, which would
    /// stay in LISTEN forever (nothing else ever matches it) and leak its buffers.
    handshaking: HashSet<FlowKey>,
    /// Sockets created and not yet removed, in any state (TIME-WAIT included).
    live: usize,
}
impl SocketRegistry {
    /// Whether a SYN for `key` gets a new socket; if so it is counted from now on.
    fn admit(&mut self, key: FlowKey, max_sockets: usize) -> bool {
        if self.handshaking.contains(&key) {
            return false;
        }
        if self.live >= max_sockets {
            trace!("TCP socket cap ({max_sockets}) reached, resetting {key:?}");
            return false;
        }
        self.handshaking.insert(key);
        self.live += 1;
        true
    }
}
type SharedRegistry = Arc<SpinMutex<SocketRegistry>>;

struct TrackedSocket {
    control: SharedControl,
    key: FlowKey,
    created: Instant,
    /// Still listed in `SocketRegistry::handshaking`.
    handshaking: bool,
}

struct TcpListenerRunner;

impl TcpListenerRunner {
    #[allow(clippy::too_many_arguments)]
    fn create(
        device: VirtualDevice,
        iface: Interface,
        iface_ingress_tx: Sender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
        control_buffer_size: Option<u32>,
        max_sockets: usize,
    ) -> Runner {
        Runner::new(async move {
            let notify = Arc::new(Notify::new());
            let registry = SharedRegistry::default();
            let (socket_tx, socket_rx) = unbounded_channel::<TcpSocketCreation>();
            let res = tokio::select! {
                v = Self::handle_packet(notify.clone(), iface_ingress_tx, iface_ingress_tx_avail.clone(), tcp_rx, stream_tx, socket_tx, registry.clone(), tcp_recv_buffer_size, tcp_send_buffer_size, control_buffer_size, max_sockets) => v,
                v = Self::handle_socket(notify, device, iface, iface_ingress_tx_avail, registry, socket_rx) => v,
            };
            res?;
            trace!("VirtDevice::poll thread exited");
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_packet(
        notify: SharedNotify,
        iface_ingress_tx: Sender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        socket_tx: UnboundedSender<TcpSocketCreation>,
        registry: SharedRegistry,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
        control_buffer_size: Option<u32>,
        max_sockets: usize,
    ) -> std::io::Result<()> {
        // The ingress queue is bounded (see `VirtualDevice`). When the interface cannot keep up
        // the frame is dropped, as a full NIC queue would: TCP retransmits it.
        let ingress = |frame: Vec<u8>| -> std::io::Result<()> {
            match iface_ingress_tx.try_send(frame) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => trace!("TCP ingress queue full, dropping frame"),
                Err(TrySendError::Closed(_)) => {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
            }
            iface_ingress_tx_avail.store(true, Ordering::Release);
            notify.notify_one();
            Ok(())
        };
        while let Some(frame) = tcp_rx.recv().await {
            let packet = match IpPacket::new_checked(frame.as_slice()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP IP packet: {:?}", err,);
                    continue;
                }
            };

            // Specially handle icmp packet by TCP interface.
            if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                ingress(frame)?;
                continue;
            }

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match TcpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, payload: {payload:?}");
                    continue;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            // TCP first handshake packet, create a new Connection, unless this is a retransmitted
            // SYN for a socket that already exists, or the socket cap is reached. In both cases
            // the frame still goes to the interface: the existing socket answers the retransmit,
            // and with no socket listening smoltcp answers the SYN with an RST.
            if packet.syn()
                && !packet.ack()
                && registry.lock().admit((src_addr, dst_addr), max_sockets)
            {
                let mut socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0u8; tcp_recv_buffer_size as usize]),
                    TcpSocketBuffer::new(vec![0u8; tcp_send_buffer_size as usize]),
                );
                socket.set_keep_alive(Some(Duration::from_secs(28)));
                // FIXME: It should follow system's setting. 7200 is Linux's default.
                socket.set_timeout(Some(Duration::from_secs(7200)));
                // NO ACK delay
                // socket.set_ack_delay(None);

                if let Err(err) = socket.listen(dst_addr) {
                    error!("listen error: {:?}", err);
                    let mut registry = registry.lock();
                    registry.handshaking.remove(&(src_addr, dst_addr));
                    registry.live -= 1;
                    continue;
                }

                trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

                let control = Arc::new(SpinMutex::new(TcpSocketControl {
                    send_buffer: RingBuffer::new(vec![
                        0u8;
                        control_buffer_size.unwrap_or(tcp_send_buffer_size)
                            as usize
                    ]),
                    send_waker: None,
                    recv_buffer: RingBuffer::new(vec![
                        0u8;
                        control_buffer_size.unwrap_or(tcp_recv_buffer_size)
                            as usize
                    ]),
                    recv_waker: None,
                    recv_state: TcpSocketState::Normal,
                    send_state: TcpSocketState::Normal,
                }));

                stream_tx
                    .send(TcpStream {
                        src_addr,
                        dst_addr,
                        notify: notify.clone(),
                        control: control.clone(),
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                socket_tx
                    .send(TcpSocketCreation {
                        control,
                        socket,
                        key: (src_addr, dst_addr),
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            }

            // Pipeline tcp stream packet
            ingress(frame)?;
        }
        Ok(())
    }

    async fn handle_socket(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        registry: SharedRegistry,
        mut socket_rx: UnboundedReceiver<TcpSocketCreation>,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);
        let mut sockets = HashMap::<SocketHandle, TrackedSocket>::new();
        loop {
            while let Ok(TcpSocketCreation {
                control,
                socket,
                key,
            }) = socket_rx.try_recv()
            {
                let handle = socket_set.add(socket);
                sockets.insert(
                    handle,
                    TrackedSocket {
                        control,
                        key,
                        created: Instant::now(),
                        handshaking: true,
                    },
                );
            }

            let before_poll = Instant::now();
            let updated_sockets = iface.poll(before_poll, &mut device, &mut socket_set);
            if matches!(
                updated_sockets,
                smoltcp::iface::PollResult::SocketStateChanged
            ) {
                trace!("VirtDevice::poll costed {}", Instant::now() - before_poll);
            }

            // Check all the sockets' status
            let mut sockets_to_remove = Vec::new();

            for (socket_handle, tracked) in sockets.iter_mut() {
                let socket_handle = *socket_handle;
                let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                let mut control = tracked.control.lock();

                if tracked.handshaking {
                    if !matches!(socket.state(), TcpState::Listen | TcpState::SynReceived) {
                        // Handshake over: a later SYN with this 4-tuple is a new connection.
                        tracked.handshaking = false;
                        registry.lock().handshaking.remove(&tracked.key);
                    } else if Instant::now() - tracked.created > HANDSHAKE_TIMEOUT {
                        trace!("TCP handshake timed out, {:?}", socket.state());
                        socket.abort();
                    }
                }

                // Remove the socket only when it is in the closed state.
                if socket.state() == TcpState::Closed {
                    sockets_to_remove.push(socket_handle);

                    control.send_state = TcpSocketState::Closed;
                    control.recv_state = TcpSocketState::Closed;

                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }

                    trace!("closed TCP connection");
                    continue;
                }

                // SHUT_WR — only close once the send_buffer has been fully
                // drained into the smoltcp socket.  Closing earlier transitions
                // the socket to FIN_WAIT_1, making can_send() return false, so
                // the send loop below never runs and the remaining data is lost.
                if matches!(control.send_state, TcpSocketState::Close)
                    && control.send_buffer.is_empty()
                {
                    trace!("closing TCP Write Half, {:?}", socket.state());

                    socket.close();
                    control.send_state = TcpSocketState::Closing;
                }

                // Check if readable
                let mut wake_receiver = false;
                while socket.can_recv() && !control.recv_buffer.is_full() {
                    let result = socket.recv(|buffer| {
                        let n = control.recv_buffer.enqueue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_receiver = true,
                        Err(err) => {
                            error!("socket recv error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.recv_state, TcpSocketState::Normal) {
                                control.recv_state = TcpSocketState::Closed;
                            }
                            wake_receiver = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                // If socket is not in ESTABLISH, FIN-WAIT-1, FIN-WAIT-2,
                // the local client have closed our receiver.
                let states = [
                    TcpState::Listen,
                    TcpState::SynReceived,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::FinWait2,
                ];
                if matches!(control.recv_state, TcpSocketState::Normal)
                    && !socket.may_recv()
                    && !states.contains(&socket.state())
                {
                    trace!("closed TCP Read Half, {:?}", socket.state());

                    // Let TcpStream::poll_read returns EOF.
                    control.recv_state = TcpSocketState::Closed;
                    wake_receiver = true;
                }

                if wake_receiver && control.recv_waker.is_some() {
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                }

                // Check if writable
                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    let result = socket.send(|buffer| {
                        let n = control.send_buffer.dequeue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_sender = true,
                        Err(err) => {
                            error!("socket send error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.send_state, TcpSocketState::Normal) {
                                control.send_state = TcpSocketState::Closed;
                            }
                            wake_sender = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                if wake_sender && control.send_waker.is_some() {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }
            }

            for socket_handle in sockets_to_remove {
                if let Some(tracked) = sockets.remove(&socket_handle) {
                    let mut registry = registry.lock();
                    if tracked.handshaking {
                        registry.handshaking.remove(&tracked.key);
                    }
                    registry.live -= 1;
                }
                socket_set.remove(socket_handle);
            }

            // Queued ingress must be drained promptly, while yielding so the
            // sibling packet handler and TUN writer can make progress.
            if iface_ingress_tx_avail.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            } else {
                // Socket I/O and inbound packets signal Notify. With no TCP
                // deadline there is no reason to poll the stack periodically.
                wait_for_work(&notify, iface.poll_delay(before_poll, &socket_set)).await;
            }
        }
    }
}

async fn wait_for_work(notify: &Notify, deadline: Option<Duration>) {
    match deadline {
        Some(Duration::ZERO) => tokio::task::yield_now().await,
        Some(delay) => {
            let _ =
                tokio::time::timeout(tokio::time::Duration::from(delay), notify.notified()).await;
        }
        None => notify.notified().await,
    }
}

pub struct TcpListener {
    stream_rx: UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub(super) fn new(
        tcp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
        mtu: usize,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
        control_buffer_size: Option<u32>,
        max_sockets: usize,
    ) -> std::io::Result<(Runner, Self)> {
        let (mut device, iface_ingress_tx, iface_ingress_tx_avail) =
            VirtualDevice::new(stack_tx, mtu);
        let iface = Self::create_interface(&mut device)?;

        let (stream_tx, stream_rx) = unbounded_channel();

        let runner = TcpListenerRunner::create(
            device,
            iface,
            iface_ingress_tx,
            iface_ingress_tx_avail,
            tcp_rx,
            stream_tx,
            tcp_recv_buffer_size,
            tcp_send_buffer_size,
            control_buffer_size,
            max_sockets,
        );

        Ok((runner, Self { stream_rx }))
    }

    fn create_interface<D>(device: &mut D) -> std::io::Result<Interface>
    where
        D: Device + ?Sized,
    {
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface.set_any_ip(true);
        Ok(iface)
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx).map(|stream| {
            stream.map(|stream| {
                let local_addr = *stream.local_addr();
                let remote_addr: SocketAddr = *stream.remote_addr();
                (stream, local_addr, remote_addr)
            })
        })
    }
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: SharedNotify,
    control: SharedControl,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut control = self.control.lock();

        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }

        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        self.notify.notify_one();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dst_addr
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        // Read from buffer
        if control.recv_buffer.is_empty() {
            // If socket is already closed / half closed, just return EOF directly.
            if matches!(control.recv_state, TcpSocketState::Closed) {
                return Ok(()).into();
            }

            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf = buf.initialize_unfilled();
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(()).into()
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut control = self.control.lock();

        // If state == Close | Closing | Closed, the TCP stream WR half is closed.
        if !matches!(control.send_state, TcpSocketState::Normal) {
            return Err(std::io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        if matches!(control.send_state, TcpSocketState::Closed) {
            return Ok(()).into();
        }

        // SHUT_WR
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        self.notify.notify_one();

        Poll::Pending
    }
}

#[cfg(test)]
mod idle_tests {
    use super::*;
    use std::{future::Future, sync::atomic::AtomicUsize, task::Wake};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_stack_does_not_schedule_periodic_wakes() {
        let (_stack, runner, _udp, _tcp) = crate::StackBuilder::default()
            .enable_tcp(true)
            .build()
            .unwrap();
        let mut runner = Box::pin(runner.unwrap());
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        assert!(runner
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_wait_resumes_on_notification_including_preexisting_signal() {
        let notify = Notify::new();
        let mut waiting = Box::pin(wait_for_work(&notify, None));
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        notify.notify_one();
        assert!(futures::poll!(waiting.as_mut()).is_ready());
        notify.notify_one();
        wait_for_work(&notify, None).await;
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_deadline_still_fires_and_notification_interrupts_timer() {
        let notify = Notify::new();
        let mut waiting = Box::pin(wait_for_work(&notify, Some(Duration::from_millis(100))));
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        tokio::time::advance(std::time::Duration::from_millis(99)).await;
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        tokio::time::advance(std::time::Duration::from_millis(1)).await;
        assert!(futures::poll!(waiting.as_mut()).is_ready());

        let mut waiting = Box::pin(wait_for_work(&notify, Some(Duration::from_secs(60))));
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        notify.notify_one();
        assert!(futures::poll!(waiting.as_mut()).is_ready());
        wait_for_work(&notify, Some(Duration::ZERO)).await;
    }
}

#[cfg(test)]
mod socket_cap_tests {
    use futures::{SinkExt, StreamExt};

    fn syn(src_port: u16) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(src_port, 443, 1000, 65535)
            .syn();
        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();
        packet
    }

    #[tokio::test]
    async fn retransmitted_syn_reuses_its_socket_and_the_cap_resets() {
        let (mut stack, runner, _udp, listener) = crate::StackBuilder::default()
            .enable_tcp(true)
            .tcp_max_sockets(2)
            .build()
            .unwrap();
        tokio::spawn(runner.unwrap());
        let mut listener = listener.unwrap();
        for port in [40000, 40000, 40001, 40002] {
            stack.send(syn(port)).await.unwrap();
        }
        let wait = std::time::Duration::from_millis(300);
        let mut streams = Vec::new();
        while let Ok(Some((_, source, _))) = tokio::time::timeout(wait, listener.next()).await {
            streams.push(source.port());
        }
        // One socket for 40000 despite the retransmit, one for 40001; 40002 is over the cap.
        assert_eq!(streams, [40000, 40001]);
        let mut reset = Vec::new();
        while let Ok(Some(Ok(packet))) = tokio::time::timeout(wait, stack.next()).await {
            let packet = etherparse::SlicedPacket::from_ip(&packet).unwrap();
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = packet.transport {
                if tcp.rst() {
                    reset.push(tcp.destination_port());
                }
            }
        }
        assert_eq!(reset, [40002]);
    }
}
