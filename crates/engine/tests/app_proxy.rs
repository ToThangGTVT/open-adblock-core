//! Host-intercepted app streams through the loopback app proxy: authentication, plain relay and
//! rule blocking, as a macOS transparent proxy uses it.
use openadblock_engine::api::{self, SocketProtector, TunnelPacketSink};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

struct Allow;
impl SocketProtector for Allow {
    fn protect(&self, _: i32) -> io::Result<()> {
        Ok(())
    }
}
struct Discard;
impl TunnelPacketSink for Discard {
    fn packet(&self, _: &[u8]) {}
}

fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 || stream.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn connect(port: u16, header: &str) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(header.as_bytes()).unwrap();
    stream
}

#[test]
fn app_streams_are_authenticated_relayed_and_filtered() {
    assert!(
        api::open_app_proxy().is_none(),
        "no listener without a tunnel"
    );
    api::replace_rules("", "", "||blocked.example^", true);
    api::start_packets(Arc::new(Allow), None, Arc::new(Discard)).unwrap();
    let endpoint = api::open_app_proxy().expect("listener");
    assert_eq!(api::open_app_proxy(), Some(endpoint.clone()), "idempotent");
    assert_eq!(endpoint.token.len(), 32);
    let upstream = echo_server();

    // Plain bytes: relayed unchanged after the sniff window.
    let mut stream = connect(
        endpoint.port,
        &format!(
            "OAB1 {} 127.0.0.1 {upstream} com.example.Browser\n",
            endpoint.token
        ),
    );
    stream.write_all(b"ping through the app proxy").unwrap();
    let mut echoed = [0u8; 26];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping through the app proxy");
    drop(stream);

    // Wrong token: closed without a byte.
    let mut stream = connect(
        endpoint.port,
        &format!(
            "OAB1 {} 127.0.0.1 {upstream} com.example.Browser\n",
            "0".repeat(32)
        ),
    );
    let mut byte = [0u8; 1];
    assert_eq!(stream.read(&mut byte).unwrap_or(0), 0);

    // A blocked HTTP host gets the engine's 204, never the upstream.
    let mut stream = connect(
        endpoint.port,
        &format!(
            "OAB1 {} 127.0.0.1 {upstream} com.example.Browser\n",
            endpoint.token
        ),
    );
    stream
        .write_all(b"GET /ad.js HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 204"), "{response:?}");

    api::stop();
    assert!(api::open_app_proxy().is_none());
    assert!(TcpStream::connect(("127.0.0.1", endpoint.port))
        .and_then(|mut s| {
            s.set_read_timeout(Some(Duration::from_secs(2)))?;
            s.read(&mut [0u8; 1])
        })
        .map_or(true, |read| read == 0));
}
