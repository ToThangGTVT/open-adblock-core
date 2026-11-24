//! C ABI of the Open AdBlock engine (`include/openadblock.h`).
//!
//! For hosts that are not JVMs: Swift on macOS/iOS, C#/C++ on Windows, C/C++ on Linux. Every
//! function forwards to `openadblock_engine::api`, so behaviour matches the JNI binding.
//!
//! Conventions:
//! - Strings in are NUL-terminated UTF-8, borrowed for the duration of the call; NULL means "".
//! - Strings out are owned by the caller and released with `oab_string_free`.
//! - Byte buffers out are released with `oab_bytes_free`.
//! - Callback structs are copied; `context` is passed back to every callback. `release`
//!   (optional) is called exactly once when the engine no longer needs the context, also when
//!   the call that received it fails. Callbacks run on engine threads and must be thread-safe.
#![allow(clippy::missing_safety_doc)]
use openadblock_engine::api::{self, EventSink, ExternalSigner, SocketProtector, TunnelPacketSink};
use std::{
    ffi::{c_char, c_void, CStr, CString},
    io,
    net::SocketAddr,
    sync::Arc,
};

/// Must equal `OAB_API_VERSION` in the header.
pub const API_VERSION: u32 = 1;
const _: () = assert!(API_VERSION == api::API_VERSION);

unsafe fn text<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        Some("")
    } else {
        CStr::from_ptr(value).to_str().ok()
    }
}

fn owned(value: &str) -> *mut c_char {
    CString::new(value.replace('\0', "")).map_or(std::ptr::null_mut(), CString::into_raw)
}

fn optional(value: &str) -> Option<&str> {
    Some(value).filter(|value| !value.is_empty())
}

/// Host context pointer; the host guarantees it may be used from any thread.
struct Context {
    pointer: *mut c_void,
    release: Option<unsafe extern "C" fn(*mut c_void)>,
}
// SAFETY: documented contract — callbacks and their context must be thread-safe.
unsafe impl Send for Context {}
unsafe impl Sync for Context {}
impl Context {
    /// Method access makes closures capture the whole `Context` (and its Send/Sync), not the
    /// raw pointer field alone.
    fn get(&self) -> *mut c_void {
        self.pointer
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            // SAFETY: called once with the context the host supplied.
            unsafe { release(self.pointer) }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OabSocketProtector {
    pub context: *mut c_void,
    /// Required. Return true once `fd` (a SOCKET on Windows) bypasses the tunnel.
    pub protect: Option<unsafe extern "C" fn(context: *mut c_void, fd: i64) -> bool>,
    /// Optional. App id owning the connection, or -1 when unknown.
    pub connection_owner: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            protocol: u8,
            source: *const c_char,
            source_port: u16,
            destination: *const c_char,
            destination_port: u16,
        ) -> i64,
    >,
    pub release: Option<unsafe extern "C" fn(context: *mut c_void)>,
}

struct HostProtector {
    context: Context,
    protect: unsafe extern "C" fn(*mut c_void, i64) -> bool,
    owner: Option<
        unsafe extern "C" fn(*mut c_void, u8, *const c_char, u16, *const c_char, u16) -> i64,
    >,
}
impl SocketProtector for HostProtector {
    fn protect(&self, fd: i32) -> io::Result<()> {
        // SAFETY: host-supplied callback with its own context.
        if unsafe { (self.protect)(self.context.pointer, fd as i64) } {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket protection failed",
            ))
        }
    }
    fn owner(&self, protocol: u8, source: SocketAddr, destination: SocketAddr) -> Option<u32> {
        let owner = self.owner?;
        let local = CString::new(source.ip().to_string()).ok()?;
        let remote = CString::new(destination.ip().to_string()).ok()?;
        // SAFETY: strings outlive the call; host callback with its own context.
        let app = unsafe {
            owner(
                self.context.pointer,
                protocol,
                local.as_ptr(),
                source.port(),
                remote.as_ptr(),
                destination.port(),
            )
        };
        u32::try_from(app).ok()
    }
}

fn protector(value: *const OabSocketProtector) -> Option<Arc<dyn SocketProtector>> {
    // SAFETY: the caller passes a valid struct or NULL.
    let value = unsafe { value.as_ref()? };
    let context = Context {
        pointer: value.context,
        release: value.release,
    };
    Some(Arc::new(HostProtector {
        protect: value.protect?,
        owner: value.connection_owner,
        context,
    }))
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OabEventListener {
    pub context: *mut c_void,
    /// Batched query-log/statistics JSON, valid only during the call.
    pub on_events: Option<unsafe extern "C" fn(context: *mut c_void, json: *const c_char)>,
    pub release: Option<unsafe extern "C" fn(context: *mut c_void)>,
}
struct HostEvents {
    context: Context,
    on_events: unsafe extern "C" fn(*mut c_void, *const c_char),
}
impl EventSink for HostEvents {
    fn batch(&self, json: &str) {
        if let Ok(json) = CString::new(json) {
            // SAFETY: host callback; the string lives until it returns.
            unsafe { (self.on_events)(self.context.pointer, json.as_ptr()) }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OabPacketSink {
    pub context: *mut c_void,
    /// One IP packet toward apps, valid only during the call.
    pub on_packet:
        Option<unsafe extern "C" fn(context: *mut c_void, data: *const u8, length: usize)>,
    pub release: Option<unsafe extern "C" fn(context: *mut c_void)>,
}
struct HostPackets {
    context: Context,
    on_packet: unsafe extern "C" fn(*mut c_void, *const u8, usize),
}
impl TunnelPacketSink for HostPackets {
    fn packet(&self, packet: &[u8]) {
        // SAFETY: host callback; the slice lives until it returns.
        unsafe { (self.on_packet)(self.context.pointer, packet.as_ptr(), packet.len()) }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OabCertificateSigner {
    pub context: *mut c_void,
    /// Writes a DER ECDSA-P256-SHA256 signature of `data` into `signature` (capacity
    /// `capacity`, 128 bytes) and returns its length, or 0 to refuse.
    pub sign: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            data: *const u8,
            length: usize,
            signature: *mut u8,
            capacity: usize,
        ) -> usize,
    >,
    pub release: Option<unsafe extern "C" fn(context: *mut c_void)>,
}

fn signer(
    value: *const OabCertificateSigner,
    public_point: *const u8,
    public_length: usize,
) -> Option<Arc<dyn api::CaSigner>> {
    // SAFETY: the caller passes a valid struct or NULL.
    let value = unsafe { value.as_ref()? };
    let context = Context {
        pointer: value.context,
        release: value.release,
    };
    let sign = value.sign?;
    if public_point.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `public_length` readable bytes.
    let point = unsafe { std::slice::from_raw_parts(public_point, public_length) }.to_vec();
    ExternalSigner::shared(point, move |data| {
        let mut signature = [0u8; 128];
        // SAFETY: both buffers are valid for the stated lengths during the call.
        let length = unsafe {
            sign(
                context.get(),
                data.as_ptr(),
                data.len(),
                signature.as_mut_ptr(),
                signature.len(),
            )
        };
        (1..=signature.len())
            .contains(&length)
            .then(|| signature[..length].to_vec())
    })
}

/// Engine release, static string.
#[no_mangle]
pub extern "C" fn oab_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn oab_api_version() -> u32 {
    api::API_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn oab_string_free(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}

#[no_mangle]
pub unsafe extern "C" fn oab_bytes_free(data: *mut u8, length: usize) {
    if !data.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            data, length,
        )));
    }
}

/// Starts the tunnel on a TUN descriptor (POSIX only). Ownership of `fd` passes to the engine on
/// entry. The protector is copied.
#[no_mangle]
pub unsafe extern "C" fn oab_start_fd(
    fd: i32,
    protector_: *const OabSocketProtector,
    dns: *const c_char,
) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let protector = protector(protector_);
        if fd < 0 {
            return false;
        }
        let fd = std::os::fd::OwnedFd::from_raw_fd(fd);
        let (Some(protector), Some(dns)) = (protector, text(dns)) else {
            return false;
        };
        api::start_fd(fd, protector, optional(dns)).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (fd, protector_, dns);
        false
    }
}

/// Starts the tunnel with host-driven packet I/O; feed packets with `oab_send_packet`.
#[no_mangle]
pub unsafe extern "C" fn oab_start_packets(
    protector_: *const OabSocketProtector,
    dns: *const c_char,
    sink: *const OabPacketSink,
) -> bool {
    let protector = protector(protector_);
    let outbound = sink.as_ref().and_then(|sink| {
        let context = Context {
            pointer: sink.context,
            release: sink.release,
        };
        let on_packet = sink.on_packet?;
        Some(Arc::new(HostPackets { context, on_packet }))
    });
    let (Some(protector), Some(outbound), Some(dns)) = (protector, outbound, text(dns)) else {
        return false;
    };
    api::start_packets(protector, optional(dns), outbound).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn oab_send_packet(data: *const u8, length: usize) -> bool {
    if data.is_null() || length == 0 || length > 65535 {
        return false;
    }
    api::send_packet(std::slice::from_raw_parts(data, length))
}

#[no_mangle]
pub extern "C" fn oab_stop() {
    api::stop();
}

#[no_mangle]
pub unsafe extern "C" fn oab_update_network(dns: *const c_char) -> bool {
    text(dns).is_some_and(|dns| api::update_network(optional(dns)))
}

#[no_mangle]
pub extern "C" fn oab_is_running() -> bool {
    api::is_running()
}

/// Copies up to `capacity` counters (order: `docs/API.md#counters`) and returns how many exist.
#[no_mangle]
pub unsafe extern "C" fn oab_counters(values: *mut i64, capacity: usize) -> usize {
    let counters = api::counters();
    if !values.is_null() {
        let count = capacity.min(counters.len());
        std::ptr::copy_nonoverlapping(counters.as_ptr(), values, count);
    }
    counters.len()
}

#[no_mangle]
pub unsafe extern "C" fn oab_configure_policy(json: *const c_char) -> bool {
    text(json).is_some_and(api::configure_policy)
}

#[no_mangle]
pub unsafe extern "C" fn oab_configure_dns(json: *const c_char) -> bool {
    text(json).is_some_and(api::configure_dns)
}

#[no_mangle]
pub unsafe extern "C" fn oab_configure_https(json: *const c_char) -> bool {
    text(json).is_some_and(api::configure_https)
}

/// Returns the JSON report (free with `oab_string_free`), or NULL on invalid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn oab_replace_rules(
    dns: *const c_char,
    browser: *const c_char,
    custom: *const c_char,
    apply: bool,
) -> *mut c_char {
    match (text(dns), text(browser), text(custom)) {
        (Some(dns), Some(browser), Some(custom)) => {
            owned(&api::replace_rules(dns, browser, custom, apply))
        }
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn oab_set_resources(
    scriptlets: *const c_char,
    redirects: *const c_char,
) -> *mut c_char {
    match (text(scriptlets), text(redirects)) {
        (Some(scriptlets), Some(redirects)) => owned(&api::set_resources(scriptlets, redirects)),
        _ => std::ptr::null_mut(),
    }
}

/// NULL (or a NULL `on_events`) detaches the current listener.
#[no_mangle]
pub unsafe extern "C" fn oab_set_event_listener(listener: *const OabEventListener) {
    let sink = listener.as_ref().and_then(|listener| {
        let context = Context {
            pointer: listener.context,
            release: listener.release,
        };
        let on_events = listener.on_events?;
        Some(Arc::new(HostEvents { context, on_events }) as Arc<dyn EventSink>)
    });
    api::set_event_sink(sink);
}

#[no_mangle]
pub extern "C" fn oab_flush_events() {
    api::flush_events();
}

#[no_mangle]
pub extern "C" fn oab_set_request_capture(app: i32, session: i64, minutes: i32) {
    api::set_request_capture(app, session, minutes);
}

/// Creates a root CA certificate. On success writes a buffer to free with `oab_bytes_free`.
#[no_mangle]
pub unsafe extern "C" fn oab_generate_root_ca(
    signer_: *const OabCertificateSigner,
    public_point: *const u8,
    public_length: usize,
    certificate: *mut *mut u8,
    certificate_length: *mut usize,
) -> bool {
    if certificate.is_null() || certificate_length.is_null() {
        return false;
    }
    let Some(der) = signer(signer_, public_point, public_length).and_then(api::generate_ca) else {
        return false;
    };
    let der = der.into_boxed_slice();
    *certificate_length = der.len();
    *certificate = Box::into_raw(der).cast();
    true
}

/// Installs the root CA. A NULL signer removes it.
#[no_mangle]
pub unsafe extern "C" fn oab_set_root_ca(
    signer_: *const OabCertificateSigner,
    public_point: *const u8,
    public_length: usize,
    certificate: *const u8,
    certificate_length: usize,
) -> bool {
    if signer_.is_null() {
        return api::set_ca(None);
    }
    if certificate.is_null() {
        return false;
    }
    let Some(signer) = signer(signer_, public_point, public_length) else {
        return false;
    };
    let der = std::slice::from_raw_parts(certificate, certificate_length).to_vec();
    api::set_ca(Some((signer, der)))
}
