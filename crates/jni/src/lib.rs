//! JNI binding for `io.github.tothanggtvt.openadblock.core.NativeBindings`.
//!
//! Only translation lives here: every call forwards to `openadblock_engine::api`. The Java side
//! (`bindings/java`) is the public API; this file must match `NativeBindings.java` exactly, which
//! `scripts/check-jni-exports.py` verifies on every build.
use jni::{
    objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue},
    sys::{jboolean, jbyteArray, jint, jlong, jlongArray, jstring, JNI_FALSE, JNI_TRUE},
    JNIEnv, JavaVM,
};
use openadblock_engine::api::{self, EventSink, ExternalSigner, SocketProtector, TunnelPacketSink};
use std::{io, net::SocketAddr, sync::Arc};

/// Calls Java from an engine thread. Attaching permanently avoids an ART attach/detach per call;
/// jni detaches the thread when it exits. Nothing else cleans up on such a thread, so each call
/// gets its own local frame and a pending exception is cleared instead of leaking into the next.
fn callback<T>(vm: &JavaVM, call: impl FnOnce(&mut JNIEnv) -> jni::errors::Result<T>) -> Option<T> {
    let mut env = vm.attach_current_thread_permanently().ok()?;
    let result = env.with_local_frame(8, call);
    if result.is_err() {
        let _ = env.exception_clear();
    }
    result.ok()
}

fn flag(value: bool) -> jboolean {
    if value {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

fn string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    if value.is_null() {
        return None;
    }
    env.get_string(value).ok().map(String::from)
}

fn new_string(env: &mut JNIEnv, value: &str) -> jstring {
    env.new_string(value)
        .map_or(std::ptr::null_mut(), |text| text.into_raw())
}

fn optional_dns(env: &mut JNIEnv, dns: &JString) -> Option<String> {
    string(env, dns).filter(|dns| !dns.is_empty())
}

struct JavaProtector {
    vm: JavaVM,
    callback: GlobalRef,
}
impl SocketProtector for JavaProtector {
    fn owner(&self, protocol: u8, source: SocketAddr, destination: SocketAddr) -> Option<u32> {
        callback(&self.vm, |env| {
            let local = JObject::from(env.new_string(source.ip().to_string())?);
            let remote = JObject::from(env.new_string(destination.ip().to_string())?);
            env.call_method(
                self.callback.as_obj(),
                "connectionOwner",
                "(ILjava/lang/String;ILjava/lang/String;I)I",
                &[
                    JValue::Int(protocol as i32),
                    JValue::Object(&local),
                    JValue::Int(source.port() as i32),
                    JValue::Object(&remote),
                    JValue::Int(destination.port() as i32),
                ],
            )
            .and_then(|value| value.i())
        })
        .and_then(|app| u32::try_from(app).ok())
    }
    fn protect(&self, fd: i32) -> io::Result<()> {
        let allowed = callback(&self.vm, |env| {
            env.call_method(
                self.callback.as_obj(),
                "protect",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .and_then(|value| value.z())
        });
        // A failed callback or pending Java exception must never bypass protection.
        if allowed == Some(true) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket protection failed",
            ))
        }
    }
}

fn protector(env: &mut JNIEnv, callback: &JObject) -> Option<Arc<dyn SocketProtector>> {
    if callback.is_null() {
        return None;
    }
    Some(Arc::new(JavaProtector {
        vm: env.get_java_vm().ok()?,
        callback: env.new_global_ref(callback).ok()?,
    }))
}

struct JavaEvents {
    vm: JavaVM,
    callback: GlobalRef,
}
impl EventSink for JavaEvents {
    fn batch(&self, json: &str) {
        callback(&self.vm, |env| {
            let text = JObject::from(env.new_string(json)?);
            env.call_method(
                self.callback.as_obj(),
                "onEvents",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&text)],
            )
            .map(|_| ())
        });
    }
}

struct JavaPackets {
    vm: JavaVM,
    callback: GlobalRef,
}
impl TunnelPacketSink for JavaPackets {
    fn packet(&self, packet: &[u8]) {
        callback(&self.vm, |env| {
            let bytes = JObject::from(env.byte_array_from_slice(packet)?);
            env.call_method(
                self.callback.as_obj(),
                "onPacket",
                "([B)V",
                &[JValue::Object(&bytes)],
            )
            .map(|_| ())
        });
    }
}

fn signer(
    env: &mut JNIEnv,
    callback: &JObject,
    public: &JByteArray,
) -> Option<Arc<dyn api::CaSigner>> {
    if callback.is_null() || public.is_null() {
        return None;
    }
    let point = env.convert_byte_array(public).ok()?;
    let vm = env.get_java_vm().ok()?;
    let callback = env.new_global_ref(callback).ok()?;
    ExternalSigner::shared(point, move |data| {
        // Signing runs on whichever thread mints a leaf certificate; a scoped attach keeps that
        // thread's JNI state untouched afterwards.
        let mut env = vm.attach_current_thread().ok()?;
        let result = env.with_local_frame(4, |env| {
            let bytes = JObject::from(env.byte_array_from_slice(data)?);
            let value = env
                .call_method(
                    callback.as_obj(),
                    "sign",
                    "([B)[B",
                    &[JValue::Object(&bytes)],
                )?
                .l()?;
            if value.is_null() {
                return Ok(None);
            }
            env.convert_byte_array(JByteArray::from(value)).map(Some)
        });
        match result {
            Ok(signature) => signature,
            Err(_) => {
                let _ = env.exception_clear();
                None
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_version(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    new_string(&mut env, api::VERSION)
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_apiVersion(
    _: JNIEnv,
    _: JClass,
) -> jint {
    api::API_VERSION as jint
}

/// Takes ownership of `fd` on entry, including every failure path.
#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_startFd(
    mut env: JNIEnv,
    _: JClass,
    fd: jint,
    callback: JObject,
    dns: JString,
) -> jboolean {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        if fd < 0 {
            return JNI_FALSE;
        }
        // SAFETY: the host transfers a detached descriptor exactly once to this function.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let Some(protector) = protector(&mut env, &callback) else {
            return JNI_FALSE;
        };
        let dns = optional_dns(&mut env, &dns);
        flag(api::start_fd(fd, protector, dns.as_deref()).is_ok())
    }
    #[cfg(not(unix))]
    {
        let _ = (&mut env, fd, callback, dns);
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_startPackets(
    mut env: JNIEnv,
    _: JClass,
    callback: JObject,
    dns: JString,
    sink: JObject,
) -> jboolean {
    let Some(protector) = protector(&mut env, &callback) else {
        return JNI_FALSE;
    };
    if sink.is_null() {
        return JNI_FALSE;
    }
    let (Ok(vm), Ok(sink)) = (env.get_java_vm(), env.new_global_ref(sink)) else {
        return JNI_FALSE;
    };
    let dns = optional_dns(&mut env, &dns);
    let outbound = Arc::new(JavaPackets { vm, callback: sink });
    flag(api::start_packets(protector, dns.as_deref(), outbound).is_ok())
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_sendPacket(
    env: JNIEnv,
    _: JClass,
    packet: JByteArray,
    offset: jint,
    length: jint,
) -> jboolean {
    if packet.is_null() || offset < 0 || !(1..=65535).contains(&length) {
        return JNI_FALSE;
    }
    let mut buffer = vec![0i8; length as usize];
    if env
        .get_byte_array_region(&packet, offset, &mut buffer)
        .is_err()
    {
        return JNI_FALSE;
    }
    // SAFETY: i8 and u8 have identical size and alignment.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len()) };
    flag(api::send_packet(bytes))
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_stop(
    _: JNIEnv,
    _: JClass,
) {
    api::stop();
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_updateNetwork(
    mut env: JNIEnv,
    _: JClass,
    dns: JString,
) -> jboolean {
    let dns = optional_dns(&mut env, &dns);
    flag(api::update_network(dns.as_deref()))
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_isRunning(
    _: JNIEnv,
    _: JClass,
) -> jboolean {
    flag(api::is_running())
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_counters(
    env: JNIEnv,
    _: JClass,
) -> jlongArray {
    let values = api::counters();
    let Ok(array) = env.new_long_array(values.len() as i32) else {
        return std::ptr::null_mut();
    };
    if env.set_long_array_region(&array, 0, &values).is_err() {
        return std::ptr::null_mut();
    }
    array.into_raw()
}

macro_rules! configure {
    ($name:ident, $call:path) => {
        #[no_mangle]
        pub extern "system" fn $name(mut env: JNIEnv, _: JClass, json: JString) -> jboolean {
            flag(string(&mut env, &json).is_some_and(|json| $call(&json)))
        }
    };
}
configure!(
    Java_io_github_tothanggtvt_openadblock_core_NativeBindings_configurePolicy,
    api::configure_policy
);
configure!(
    Java_io_github_tothanggtvt_openadblock_core_NativeBindings_configureDns,
    api::configure_dns
);
configure!(
    Java_io_github_tothanggtvt_openadblock_core_NativeBindings_configureHttps,
    api::configure_https
);

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_replaceRules(
    mut env: JNIEnv,
    _: JClass,
    dns: JString,
    browser: JString,
    custom: JString,
    apply: jboolean,
) -> jstring {
    let (Some(dns), Some(browser), Some(custom)) = (
        string(&mut env, &dns),
        string(&mut env, &browser),
        string(&mut env, &custom),
    ) else {
        return std::ptr::null_mut();
    };
    let report = api::replace_rules(&dns, &browser, &custom, apply == JNI_TRUE);
    new_string(&mut env, &report)
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_setResources(
    mut env: JNIEnv,
    _: JClass,
    scriptlets: JString,
    redirects: JString,
) -> jstring {
    let (Some(scriptlets), Some(redirects)) =
        (string(&mut env, &scriptlets), string(&mut env, &redirects))
    else {
        return std::ptr::null_mut();
    };
    let result = api::set_resources(&scriptlets, &redirects);
    new_string(&mut env, &result)
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_setEventListener(
    env: JNIEnv,
    _: JClass,
    listener: JObject,
) {
    if listener.is_null() {
        api::set_event_sink(None);
        return;
    }
    if let (Ok(vm), Ok(callback)) = (env.get_java_vm(), env.new_global_ref(listener)) {
        api::set_event_sink(Some(Arc::new(JavaEvents { vm, callback })));
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_flushEvents(
    _: JNIEnv,
    _: JClass,
) {
    api::flush_events();
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_setRequestCapture(
    _: JNIEnv,
    _: JClass,
    app: jint,
    session: jlong,
    minutes: jint,
) {
    api::set_request_capture(app, session, minutes);
}

#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_generateRootCa(
    mut env: JNIEnv,
    _: JClass,
    callback: JObject,
    public: JByteArray,
) -> jbyteArray {
    signer(&mut env, &callback, &public)
        .and_then(api::generate_ca)
        .and_then(|der| env.byte_array_from_slice(&der).ok())
        .map_or(std::ptr::null_mut(), |array| array.into_raw())
}

/// A null signer removes the root CA.
#[no_mangle]
pub extern "system" fn Java_io_github_tothanggtvt_openadblock_core_NativeBindings_setRootCa(
    mut env: JNIEnv,
    _: JClass,
    callback: JObject,
    public: JByteArray,
    certificate: JByteArray,
) -> jboolean {
    if callback.is_null() {
        return flag(api::set_ca(None));
    }
    let Some(signer) = signer(&mut env, &callback, &public) else {
        return JNI_FALSE;
    };
    if certificate.is_null() {
        return JNI_FALSE;
    }
    let Ok(der) = env.convert_byte_array(&certificate) else {
        return JNI_FALSE;
    };
    flag(api::set_ca(Some((signer, der))))
}
