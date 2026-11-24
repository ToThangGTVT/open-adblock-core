//! GoodbyeDPI-style DPI circumvention without root.
//!
//! GoodbyeDPI rewrites packets with WinDivert. Here the engine owns every outbound socket, so the
//! same tricks are applied to the bytes it writes:
//! - `-f`/`-e`/`--frag-by-sni`: the request is cut into separate TCP segments, one cut inside
//!   the hostname, so DPI that inspects single packets never sees the whole TLS SNI or HTTP Host;
//! - `-r`/`-s`/`-m`/`-a`: `Host:` becomes `hoSt:`, loses its space, gets mixed case, and the
//!   request line gets an extra space;
//! - `-k`: later requests on a keep-alive HTTP connection get the same treatment;
//! - `--reverse-frag`: the first piece leaves with TTL 1, dies at the first hop and is resent by
//!   the kernel after the rest, so the server gets the pieces out of order;
//! - `--set-ttl` (fake request): the first piece is first sent as a decoy with another hostname
//!   and a low TTL, so DPI on the way reads the decoy and the server never gets it. The decoy is
//!   spliced from memory the kernel keeps referencing, and the real bytes are copied into that
//!   memory before the kernel retransmits it (the technique ByeDPI uses on Android without root);
//! - `-q`: QUIC is dropped so browsers use TCP, where all of the above applies (see `udp`);
//! - `--blacklist`/`--allow-no-sni`: optionally only for listed hosts.
//!
//! Not possible without raw sockets: wrong checksum or sequence fakes (`--wrong-chksum`,
//! `--wrong-seq`), automatic TTL (`--auto-ttl`) and dropping injected redirects/resets (`-p`).
use serde::Deserialize;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    ops::Range,
    os::fd::AsRawFd,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// User settings, sent from the app inside the traffic policy as `dpi`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Options {
    pub enabled: bool,
    /// `-f`: first HTTP segment size; 0 turns it off. Also used for keep-alive requests (`-k`).
    pub http_split: usize,
    /// `-e`: first HTTPS segment size; 0 turns it off.
    pub https_split: usize,
    /// `--frag-by-sni`, cutting in the middle of the hostname rather than before it.
    pub split_at_host: bool,
    /// `-r`
    pub host_replace: bool,
    /// `-s`
    pub host_remove_space: bool,
    /// `-m`
    pub host_mix_case: bool,
    /// `-a`, which implies `-s`.
    pub method_space: bool,
    /// `-k`
    pub keep_alive: bool,
    /// `--reverse-frag`
    pub disorder: bool,
    /// `--set-ttl`: send a decoy first piece with [`Self::fake_ttl`].
    pub fake: bool,
    pub fake_ttl: u8,
    /// `-q`
    pub block_quic: bool,
    /// `--blacklist`: when not empty, only these hosts and their subdomains are touched.
    pub blacklist: Vec<String>,
    /// `--allow-no-sni`: with a blacklist, also touch connections without a known hostname.
    pub allow_no_sni: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            enabled: false,
            http_split: 2,
            https_split: 2,
            split_at_host: true,
            host_replace: true,
            host_remove_space: true,
            host_mix_case: false,
            method_space: false,
            keep_alive: true,
            disorder: false,
            fake: false,
            fake_ttl: 5,
            block_quic: true,
            blacklist: vec![],
            allow_no_sni: false,
        }
    }
}
impl Options {
    /// Lowercases and dedupes the blacklist; `*.example.com` and `.example.com` mean the domain.
    pub fn normalize(&mut self) {
        let mut list: Vec<String> = self
            .blacklist
            .iter()
            .map(|d| {
                d.trim()
                    .trim_start_matches("*.")
                    .trim_matches('.')
                    .to_ascii_lowercase()
            })
            .filter(|d| !d.is_empty() && d.len() <= 253)
            .collect();
        list.sort_unstable();
        list.dedup();
        list.truncate(10_000);
        self.blacklist = list;
        self.fake_ttl = self.fake_ttl.clamp(1, 64);
    }
    /// Whether a connection to `host` is in scope of the blacklist.
    pub fn listed(&self, host: Option<&str>) -> bool {
        if self.blacklist.is_empty() {
            return true;
        }
        match host {
            Some(host) => self.blacklist.iter().any(|d| {
                host == d
                    || host
                        .strip_suffix(d.as_str())
                        .is_some_and(|p| p.ends_with('.'))
            }),
            None => self.allow_no_sni,
        }
    }
}

/// Whether the user turned on DPI circumvention.
pub fn enabled() -> bool {
    crate::policy::current().dpi.enabled
}

/// Whether QUIC to `host` (reverse-looked-up, may be unknown) should be dropped (`-q`).
pub fn drops_quic(host: Option<&str>) -> bool {
    let policy = crate::policy::current();
    let o = &policy.dpi;
    o.enabled && o.block_quic && (o.blacklist.is_empty() || host.is_none() || o.listed(host))
}

fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

const METHODS: &[&[u8]] = &[
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE",
];

/// Length of the header section of an HTTP/1.x request including the final CRLF, but not the
/// blank line.
fn http_headers(bytes: &[u8]) -> Option<usize> {
    let line = bytes.windows(2).position(|w| w == b"\r\n")?;
    let mut words = bytes[..line]
        .split(|&c| c == b' ')
        .filter(|w| !w.is_empty());
    if !METHODS.contains(&words.next()?)
        || words.next().is_none()
        || !words.next()?.starts_with(b"HTTP/1.")
    {
        return None;
    }
    Some(bytes.windows(4).position(|w| w == b"\r\n\r\n")? + 2)
}

/// Start of the `Host` header line within an HTTP request header section.
fn host_line(headers: &[u8]) -> Option<usize> {
    let mut at = headers.windows(2).position(|w| w == b"\r\n")? + 2;
    while at < headers.len() {
        let end = at + headers[at..].windows(2).position(|w| w == b"\r\n")?;
        if end - at >= 5 && headers[at..at + 5].eq_ignore_ascii_case(b"host:") {
            return Some(at);
        }
        at = end + 2;
    }
    None
}

/// Hostname (without port) of a Host header value starting at `start`: its byte range.
fn host_value(bytes: &[u8], start: usize) -> Range<usize> {
    let len = bytes[start..]
        .iter()
        .take_while(|&&c| !matches!(c, b'\r' | b':' | b' ' | b'\t'))
        .count();
    start..start + len
}

/// Rewritten HTTP request and the hostname range in it. Returns None if `bytes` is not a
/// complete request header section.
pub fn rewrite_http(bytes: &[u8], o: &Options) -> Option<(Vec<u8>, Option<Range<usize>>)> {
    let headers = http_headers(bytes)?;
    let mut out = Vec::with_capacity(bytes.len() + 2);
    let line_end = bytes.windows(2).position(|w| w == b"\r\n")?;
    let mut copied = 0;
    if o.method_space {
        // `GET /` becomes `GET  /`.
        let space = bytes[..line_end].iter().position(|&c| c == b' ')?;
        out.extend_from_slice(&bytes[..=space]);
        out.push(b' ');
        copied = space + 1;
    }
    let Some(line) = host_line(&bytes[..headers]) else {
        out.extend_from_slice(&bytes[copied..]);
        return Some((out, None));
    };
    out.extend_from_slice(&bytes[copied..line]);
    out.extend_from_slice(if o.host_replace {
        b"hoSt:"
    } else {
        &bytes[line..line + 5]
    });
    let mut value = line + 5;
    let spaces = bytes[value..]
        .iter()
        .take_while(|c| matches!(c, b' ' | b'\t'))
        .count();
    if !(o.host_remove_space || o.method_space) {
        out.extend_from_slice(&bytes[value..value + spaces]);
    }
    value += spaces;
    let host = host_value(bytes, value);
    let start = out.len();
    for (i, &c) in bytes[host.clone()].iter().enumerate() {
        out.push(match (o.host_mix_case, i % 2) {
            (true, 1) => c.to_ascii_uppercase(),
            (true, _) => c.to_ascii_lowercase(),
            _ => c,
        });
    }
    let range = start..out.len();
    out.extend_from_slice(&bytes[host.end..]);
    Some((out, Some(range).filter(|r| r.len() >= 2)))
}

/// How one piece of the output leaves the socket.
#[derive(Debug, PartialEq)]
pub enum Mode {
    Normal,
    /// TTL 1: dropped at the first hop, then retransmitted by the kernel with the normal TTL.
    Disorder,
    /// Sent first with these decoy bytes (same length) and the fake TTL, then retransmitted
    /// with the real bytes.
    Fake(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub struct Piece {
    pub end: usize,
    pub mode: Mode,
}

/// What to send for one client write: possibly rewritten bytes, cut into pieces.
#[derive(Debug, PartialEq)]
pub struct Plan {
    pub data: Vec<u8>,
    pub pieces: Vec<Piece>,
    pub http: bool,
}

/// Same-length decoy for `piece`, with the hostname bytes in `host` replaced by random letters.
fn decoy(piece: &[u8], host: Range<usize>) -> Vec<u8> {
    let mut out = piece.to_vec();
    let mut random = vec![0u8; host.len()];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random);
    for (i, r) in host.zip(random) {
        if let Some(c) = out.get_mut(i) {
            if c.is_ascii_alphanumeric() {
                *c = b'a' + r % 26;
            }
        }
    }
    out
}

/// Plans one write. `first` is the connection's first write; later ones are only planned as
/// keep-alive HTTP requests. `hint` is the hostname the sniffer or proxy already knows.
pub fn plan(bytes: &[u8], hint: Option<&str>, o: &Options, first: bool) -> Option<Plan> {
    if !o.enabled || bytes.is_empty() {
        return None;
    }
    let (data, host, split, http) = if first && bytes[0] == 22 {
        let range = hint
            .filter(|h| h.len() >= 2)
            .and_then(|h| find_ascii_ci(bytes, h.as_bytes()).map(|at| at..at + h.len()));
        if !o.listed(hint) {
            return None;
        }
        (bytes.to_vec(), range, o.https_split, false)
    } else if first || o.keep_alive {
        let headers = http_headers(bytes)?;
        let name = host_line(&bytes[..headers]).map(|line| {
            let start = line
                + 5
                + bytes[line + 5..]
                    .iter()
                    .take_while(|c| matches!(c, b' ' | b'\t'))
                    .count();
            String::from_utf8_lossy(&bytes[host_value(bytes, start)]).to_ascii_lowercase()
        });
        if !o.listed(name.as_deref().or(hint)) {
            return None;
        }
        let (data, range) = rewrite_http(bytes, o)?;
        (data, range, o.http_split, true)
    } else {
        return None;
    };
    let mut cuts = vec![];
    if split > 0 {
        cuts.push(split);
    }
    if let (true, Some(range)) = (o.split_at_host, &host) {
        cuts.push(range.start + range.len() / 2);
    }
    let mut pieces = vec![];
    // The decoy must hold the whole hostname, so the fake piece ends where it ends.
    match (&host, first && o.fake) {
        (Some(range), true) if range.end < data.len() => {
            cuts.retain(|&c| c > range.end);
            pieces.push(Piece {
                end: range.end,
                mode: Mode::Fake(decoy(&data[..range.end], range.clone())),
            });
        }
        _ => {}
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts.retain(|&c| c > 0 && c < data.len());
    let disorder = first && o.disorder && pieces.is_empty();
    for (i, end) in cuts.into_iter().enumerate() {
        let mode = if disorder && i == 0 {
            Mode::Disorder
        } else {
            Mode::Normal
        };
        pieces.push(Piece { end, mode });
    }
    if pieces.is_empty() && data == bytes {
        return None;
    }
    pieces.push(Piece {
        end: data.len(),
        mode: Mode::Normal,
    });
    Some(Plan { data, pieces, http })
}

/// Socket operations [`Desync`] needs beyond reading and writing.
pub trait Socket: AsyncRead + AsyncWrite + AsRawFd + Unpin {
    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    /// Runs a raw write syscall, clearing readiness when it would block.
    fn try_raw_write(&self, f: &mut dyn FnMut() -> io::Result<usize>) -> io::Result<usize>;
    fn is_ipv6(&self) -> bool;
}
impl Socket for tokio::net::TcpStream {
    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_ready(cx)
    }
    fn try_raw_write(&self, f: &mut dyn FnMut() -> io::Result<usize>) -> io::Result<usize> {
        self.try_io(tokio::io::Interest::WRITABLE, f)
    }
    fn is_ipv6(&self) -> bool {
        self.local_addr().is_ok_and(|a| a.is_ipv6())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod sys {
    use std::{
        io,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };

    /// Bytes queued in the kernel but not yet handed to the network. Zero when unknown.
    pub fn unsent(fd: i32) -> i32 {
        let mut pending: libc::c_int = 0;
        // SAFETY: fd is a live socket owned by the caller; SIOCOUTQNSD writes one int.
        if unsafe { libc::ioctl(fd, libc::SIOCOUTQNSD as _, &mut pending) } == 0 {
            pending
        } else {
            0
        }
    }

    fn check(result: libc::c_int) -> io::Result<()> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Sets the unicast TTL / hop limit; None restores the system default.
    pub fn set_ttl(fd: i32, v6: bool, ttl: Option<u8>) -> io::Result<()> {
        let value: libc::c_int = ttl.map_or(-1, libc::c_int::from);
        let (level, name) = if v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TTL)
        };
        // SAFETY: plain setsockopt with a c_int value.
        check(unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as _,
            )
        })
    }

    /// Decoy bytes in shared memory, gifted to a pipe and then spliced into the socket so the
    /// kernel keeps referencing (not copying) these pages until the data is acknowledged.
    pub struct Fake {
        map: *mut u8,
        len: usize,
        read: OwnedFd,
        _write: OwnedFd,
        left: usize,
    }
    // SAFETY: the mapping is owned exclusively by this value.
    unsafe impl Send for Fake {}
    unsafe impl Sync for Fake {}

    impl Fake {
        pub fn new(decoy: &[u8]) -> io::Result<Self> {
            let len = decoy.len();
            if len == 0 || len > 16 * 1024 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            // SAFETY: anonymous shared mapping of `len` bytes, checked below.
            let map = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                    -1,
                    0,
                )
            };
            if map == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let map = map.cast::<u8>();
            let mut fds = [0; 2];
            // SAFETY: pipe2 fills two descriptors on success.
            if let Err(error) =
                check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) })
            {
                // SAFETY: unmapping the mapping created above.
                unsafe { libc::munmap(map.cast(), len) };
                return Err(error);
            }
            // SAFETY: both descriptors were just created and are owned here.
            let (read, write) =
                unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            let fake = Self {
                map,
                len,
                read,
                _write: write,
                left: len,
            };
            // SAFETY: the mapping is `len` bytes long and not shared with anyone yet.
            unsafe { std::ptr::copy_nonoverlapping(decoy.as_ptr(), map, len) };
            let mut queued = 0;
            while queued < len {
                let vec = libc::iovec {
                    iov_base: unsafe { map.add(queued) }.cast(),
                    iov_len: len - queued,
                };
                // SAFETY: the iovec points into the live mapping.
                let n = unsafe {
                    libc::vmsplice(
                        fds[1],
                        &vec,
                        1,
                        libc::SPLICE_F_GIFT | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if n <= 0 {
                    return Err(io::Error::last_os_error());
                }
                queued += n as usize;
            }
            Ok(fake)
        }
        pub fn left(&self) -> usize {
            self.left
        }
        /// Moves queued decoy bytes into the socket; WouldBlock when its buffer is full.
        pub fn splice_to(&mut self, socket: i32) -> io::Result<usize> {
            // SAFETY: both descriptors are live; null offsets mean the current position.
            let n = unsafe {
                libc::splice(
                    self.read.as_raw_fd(),
                    std::ptr::null_mut(),
                    socket,
                    std::ptr::null_mut(),
                    self.left,
                    libc::SPLICE_F_NONBLOCK,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.left -= n as usize;
            Ok(n as usize)
        }
        /// Overwrites the decoy with the real bytes, which the kernel retransmits.
        pub fn reveal(&mut self, real: &[u8]) {
            let n = real.len().min(self.len);
            // SAFETY: at most `len` bytes into the live mapping.
            unsafe { std::ptr::copy_nonoverlapping(real.as_ptr(), self.map, n) };
        }
    }
    impl Drop for Fake {
        fn drop(&mut self) {
            // SAFETY: unmaps our own mapping; the kernel keeps its page references.
            unsafe { libc::munmap(self.map.cast(), self.len) };
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod sys {
    use std::io;
    pub fn unsent(_: i32) -> i32 {
        0
    }
    pub fn set_ttl(fd: i32, v6: bool, ttl: Option<u8>) -> io::Result<()> {
        let value: libc::c_int = ttl.map_or(64, libc::c_int::from);
        let (level, name) = if v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TTL)
        };
        // SAFETY: plain setsockopt with a c_int value.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as _,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    /// Splicing pages into a socket is Linux-only; fakes fall back to disorder elsewhere.
    pub struct Fake;
    impl Fake {
        pub fn new(_: &[u8]) -> io::Result<Self> {
            Err(io::ErrorKind::Unsupported.into())
        }
        pub fn left(&self) -> usize {
            0
        }
        pub fn splice_to(&mut self, _: i32) -> io::Result<usize> {
            Err(io::ErrorKind::Unsupported.into())
        }
        pub fn reveal(&mut self, _: &[u8]) {}
    }
}

const PAUSE: Duration = Duration::from_millis(1);
const MAX_WAITS: u8 = 30;

enum After {
    Nothing,
    RestoreTtl,
    Reveal(Range<usize>),
}
struct Pause {
    sleep: Pin<Box<tokio::time::Sleep>>,
    waited: u8,
    after: After,
}
impl Pause {
    fn new(after: After) -> Self {
        Self {
            sleep: Box::pin(tokio::time::sleep(PAUSE)),
            waited: 0,
            after,
        }
    }
}

/// Wraps an outbound socket and applies [`plan`] to its first write (and to later keep-alive
/// HTTP requests). Planned bytes are buffered and sent piece by piece: between pieces it waits,
/// briefly and bounded, until the kernel has sent the previous one so pieces never merge.
/// Reads and unplanned writes pass straight through.
pub struct Desync<S> {
    inner: S,
    host: Option<String>,
    options: Arc<Options>,
    first: bool,
    http: bool,
    v6: bool,
    out: Vec<u8>,
    sent: usize,
    pieces: VecDeque<Piece>,
    pause: Option<Pause>,
    fake: Option<sys::Fake>,
}

impl<S: Socket> Desync<S> {
    /// `host` is the hostname already known; `active` false makes this a passthrough.
    pub fn new(inner: S, host: Option<String>, active: bool) -> Self {
        let options = if active {
            crate::policy::current().dpi.clone()
        } else {
            Options::default()
        };
        Self::with_options(inner, host, Arc::new(options))
    }
    pub fn with_options(inner: S, host: Option<String>, options: Arc<Options>) -> Self {
        let v6 = inner.is_ipv6();
        Self {
            inner,
            host,
            options,
            first: true,
            http: false,
            v6,
            out: vec![],
            sent: 0,
            pieces: VecDeque::new(),
            pause: None,
            fake: None,
        }
    }
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.inner.as_raw_fd();
        loop {
            if let Some(pause) = self.pause.as_mut() {
                while pause.waited < MAX_WAITS && sys::unsent(fd) > 0 {
                    ready!(pause.sleep.as_mut().poll(cx));
                    pause.waited += 1;
                    pause
                        .sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + PAUSE);
                }
                let after = std::mem::replace(&mut pause.after, After::Nothing);
                self.pause = None;
                match after {
                    After::Nothing => {}
                    After::RestoreTtl => sys::set_ttl(fd, self.v6, None)?,
                    After::Reveal(range) => {
                        if let Some(mut fake) = self.fake.take() {
                            fake.reveal(&self.out[range]);
                        }
                        sys::set_ttl(fd, self.v6, None)?;
                    }
                }
            }
            if self.sent >= self.out.len() {
                self.out = vec![];
                self.sent = 0;
                self.pieces.clear();
                return Poll::Ready(Ok(()));
            }
            let Some(piece) = self.pieces.front_mut() else {
                self.pieces.push_back(Piece {
                    end: self.out.len(),
                    mode: Mode::Normal,
                });
                continue;
            };
            let end = piece.end.min(self.out.len());
            let after = match &piece.mode {
                Mode::Normal | Mode::Disorder => {
                    let disorder = piece.mode == Mode::Disorder;
                    if disorder {
                        sys::set_ttl(fd, self.v6, Some(1))?;
                    }
                    let n = ready!(
                        Pin::new(&mut self.inner).poll_write(cx, &self.out[self.sent..end])
                    )?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    self.sent += n;
                    if self.sent < end {
                        continue;
                    }
                    if disorder {
                        After::RestoreTtl
                    } else {
                        After::Nothing
                    }
                }
                Mode::Fake(decoy) => {
                    let start = end - decoy.len();
                    if self.fake.is_none() {
                        match sys::Fake::new(decoy) {
                            Ok(fake) => self.fake = Some(fake),
                            Err(_) => {
                                // No splice here: still reorder the pieces.
                                piece.mode = Mode::Disorder;
                                continue;
                            }
                        }
                        sys::set_ttl(fd, self.v6, Some(self.options.fake_ttl))?;
                    }
                    let fake = self.fake.as_mut().expect("created above");
                    while fake.left() > 0 {
                        ready!(self.inner.poll_writable(cx))?;
                        match self.inner.try_raw_write(&mut || fake.splice_to(fd)) {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                    self.sent = end;
                    After::Reveal(start..end)
                }
            };
            self.pieces.pop_front();
            // Always wait after a TTL change; between plain pieces only if more follows.
            if self.sent < self.out.len() || !matches!(after, After::Nothing) {
                self.pause = Some(Pause::new(after));
            }
        }
    }
}

impl<S: Socket> AsyncRead for Desync<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: Socket> AsyncWrite for Desync<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        let first = std::mem::replace(&mut this.first, false);
        if this.options.enabled && !buf.is_empty() && (first || this.http) {
            if let Some(plan) = plan(buf, this.host.as_deref(), &this.options, first) {
                this.http = plan.http;
                this.out = plan.data;
                this.sent = 0;
                this.pieces = plan.pieces.into();
                // Start sending now; what is left goes out on the next write, flush or shutdown.
                if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(buf.len()));
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> Options {
        Options {
            enabled: true,
            ..Options::default()
        }
    }

    fn hello(host: &str) -> Vec<u8> {
        let mut hello = vec![22, 3, 1, 0, 60];
        hello.extend_from_slice(&[7; 30]);
        hello.extend_from_slice(host.as_bytes());
        hello.extend_from_slice(&[9; 15]);
        hello
    }

    #[test]
    fn http_host_tricks() {
        let request = b"GET / HTTP/1.1\r\nHost:  example.com:8080\r\nAccept: */*\r\n\r\nbody";
        let (out, host) = rewrite_http(request, &on()).unwrap();
        assert_eq!(
            out,
            b"GET / HTTP/1.1\r\nhoSt:example.com:8080\r\nAccept: */*\r\n\r\nbody"
        );
        assert_eq!(&out[host.unwrap()], b"example.com");
        let mixed = Options {
            host_mix_case: true,
            method_space: true,
            host_replace: false,
            host_remove_space: false,
            ..on()
        };
        let (out, _) = rewrite_http(request, &mixed).unwrap();
        assert_eq!(
            out,
            b"GET  / HTTP/1.1\r\nHost:eXaMpLe.cOm:8080\r\nAccept: */*\r\n\r\nbody"
        );
        assert_eq!(rewrite_http(b"\x16\x03\x01", &on()), None);
        assert_eq!(rewrite_http(b"NOTHTTP x y\r\n\r\n", &on()), None);
    }

    #[test]
    fn http_cut_after_two_bytes_and_inside_host() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let plan = plan(request, None, &on(), true).unwrap();
        assert_eq!(plan.data, b"GET / HTTP/1.1\r\nhoSt:example.com\r\n\r\n");
        let ends: Vec<_> = plan.pieces.iter().map(|p| p.end).collect();
        assert_eq!(ends, vec![2, 21 + 5, plan.data.len()]);
        assert!(plan.pieces.iter().all(|p| p.mode == Mode::Normal));
    }

    #[test]
    fn tls_cuts_disorder_and_fake() {
        let data = hello("Example.COM");
        let plan_of = |o: &Options| plan(&data, Some("example.com"), o, true).unwrap();
        let ends = |p: &Plan| p.pieces.iter().map(|p| p.end).collect::<Vec<_>>();
        let plain = plan_of(&on());
        assert_eq!(ends(&plain), vec![2, 35 + 5, data.len()]);
        let disorder = plan_of(&Options {
            disorder: true,
            ..on()
        });
        assert_eq!(disorder.pieces[0].mode, Mode::Disorder);
        let fake = plan_of(&Options {
            fake: true,
            disorder: true,
            ..on()
        });
        assert_eq!(ends(&fake), vec![46, data.len()]);
        let Mode::Fake(decoy) = &fake.pieces[0].mode else {
            panic!("fake first")
        };
        assert_eq!(decoy.len(), 46);
        assert_eq!(decoy[..35], data[..35]);
        assert_ne!(decoy[35..46], data[35..46]);
        assert_eq!(decoy[42], b'.');
        assert_eq!(
            plan(&data, None, &on(), true).map(|p| ends(&p)),
            Some(vec![2, data.len()])
        );
        assert_eq!(plan(b"\x00binary", None, &on(), true), None);
        assert_eq!(
            plan(&data, Some("example.com"), &Options::default(), true),
            None
        );
    }

    #[test]
    fn keep_alive_requests_and_blacklist() {
        let request = b"GET /2 HTTP/1.1\r\nHost: a.example.com\r\n\r\n";
        assert!(plan(request, None, &on(), false).is_some());
        assert_eq!(
            plan(
                request,
                None,
                &Options {
                    keep_alive: false,
                    ..on()
                },
                false
            ),
            None
        );
        assert_eq!(
            plan(&hello("example.com"), Some("example.com"), &on(), false),
            None
        );
        let mut listed = Options {
            blacklist: vec![" *.Example.com ".into(), "blocked.net".into()],
            ..on()
        };
        listed.normalize();
        assert_eq!(listed.blacklist, vec!["blocked.net", "example.com"]);
        assert!(plan(request, None, &listed, true).is_some());
        assert_eq!(
            plan(
                b"GET / HTTP/1.1\r\nHost: other.org\r\n\r\n",
                None,
                &listed,
                true
            ),
            None
        );
        assert_eq!(
            plan(
                b"GET / HTTP/1.1\r\nHost: notexample.com\r\n\r\n",
                None,
                &listed,
                true
            ),
            None
        );
        assert_eq!(plan(&hello("xx"), None, &listed, true), None);
        let no_sni = Options {
            allow_no_sni: true,
            ..listed
        };
        assert!(plan(&hello("xx"), None, &no_sni, true).is_some());
    }

    async fn roundtrip(options: Options, writes: &[&[u8]]) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = vec![];
            socket.read_to_end(&mut received).await.unwrap();
            received
        });
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut desync =
            Desync::with_options(stream, Some("blocked.example".into()), Arc::new(options));
        for write in writes {
            desync.write_all(write).await.unwrap();
            desync.flush().await.unwrap();
        }
        desync.shutdown().await.unwrap();
        server.await.unwrap()
    }

    #[tokio::test]
    async fn desync_delivers_every_byte_in_order() {
        let data = hello("blocked.example");
        for options in [
            on(),
            Options {
                disorder: true,
                ..on()
            },
            Options { fake: true, ..on() },
            Options::default(),
        ] {
            let mut expected = data.clone();
            expected.extend_from_slice(b"rest");
            assert_eq!(roundtrip(options, &[&data, b"rest"]).await, expected);
        }
    }

    #[tokio::test]
    async fn keep_alive_requests_are_rewritten_on_the_wire() {
        let first = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
        let second = b"GET /next HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
        let received = roundtrip(
            Options {
                disorder: true,
                ..on()
            },
            &[first, second],
        )
        .await;
        assert_eq!(
            received,
            b"GET / HTTP/1.1\r\nhoSt:blocked.example\r\n\r\nGET /next HTTP/1.1\r\nhoSt:blocked.example\r\n\r\n"
        );
    }
}
