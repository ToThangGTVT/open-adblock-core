//! Loopback entry for TCP streams a host intercepts per application, such as a macOS
//! `NETransparentProxyProvider` that hands over only browser flows. Each stream gets the same
//! filtering as tunnelled TCP (`tcp::relay`): rules, HTTPS decryption for the apps selected in
//! `configure_https`, and a protected upstream connection.
//!
//! Protocol, per TCP connection to `127.0.0.1:<port>`:
//!
//! ```text
//! OAB1 <token> <destination host or IP> <destination port> <app id>\n
//! <the app's bytes, both directions, unchanged>
//! ```
//!
//! The token is random per engine run and only known in-process, so other local programs cannot
//! use the listener. The app id is what `configure_https` lists (a bundle identifier on macOS).
use crate::{
    policy::Owner,
    sockets::{Protector, Stats},
    tcp::{relay, Refusal},
};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::TcpListener,
    sync::Semaphore,
};

/// Where a host connects, and the secret it sends first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
}

/// Header line limit; host names are at most 253 bytes.
const HEADER_LIMIT: u64 = 512;

/// Binds the loopback listener; the caller spawns `serve` on the engine runtime.
pub fn bind() -> io::Result<(std::net::TcpListener, Endpoint)> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let mut secret = [0u8; 16];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| io::Error::other("no randomness"))?;
    let token = secret.iter().map(|b| format!("{b:02x}")).collect();
    let port = listener.local_addr()?.port();
    Ok((listener, Endpoint { port, token }))
}

pub async fn serve(
    listener: std::net::TcpListener,
    token: String,
    protector: Arc<dyn Protector>,
    stats: Arc<Stats>,
) {
    let Ok(listener) = TcpListener::from_std(listener) else {
        return;
    };
    let permits = Arc::new(Semaphore::new(256));
    let token: Arc<str> = token.into();
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let (token, protector, stats) = (token.clone(), protector.clone(), stats.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            let mut client = BufReader::new(stream);
            let header =
                tokio::time::timeout(Duration::from_secs(5), read_header(&mut client)).await;
            let Ok(Some(header)) = header else { return };
            let Some(request) = Request::parse(&header, &token) else {
                return;
            };
            let Some(destination) = request.resolve().await else {
                return;
            };
            if destination.is_ipv6() && !crate::sockets::ipv6_available() {
                return;
            }
            relay(
                client,
                destination,
                request.owner(),
                protector,
                stats,
                Refusal::Close,
            )
            .await;
        });
    }
}

async fn read_header(client: &mut BufReader<tokio::net::TcpStream>) -> Option<String> {
    let mut line = String::new();
    let read = (&mut *client)
        .take(HEADER_LIMIT)
        .read_line(&mut line)
        .await
        .ok()?;
    (read > 0 && line.ends_with('\n')).then_some(line)
}

#[derive(Debug, PartialEq, Eq)]
struct Request {
    host: String,
    port: u16,
    app: String,
}

impl Request {
    fn parse(line: &str, token: &str) -> Option<Self> {
        let mut parts = line.trim_end_matches(['\r', '\n']).split(' ');
        if parts.next()? != "OAB1" || !constant_time_eq(parts.next()?, token) {
            return None;
        }
        let host = parts.next()?.trim_start_matches('[').trim_end_matches(']');
        let port = parts.next()?.parse().ok().filter(|port| *port != 0)?;
        let app = parts.next()?;
        if parts.next().is_some() || host.is_empty() || app.is_empty() || app.len() > 255 {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            port,
            app: app.to_owned(),
        })
    }

    async fn resolve(&self) -> Option<SocketAddr> {
        if let Ok(ip) = self.host.parse() {
            return Some(SocketAddr::new(ip, self.port));
        }
        if !crate::mitm::valid_domain(&self.host) {
            return None;
        }
        // A name, not an address: resolve through the system, which asks the engine's own DNS.
        tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .ok()?
            .find(|address| !address.ip().is_unspecified())
    }

    /// Host-proxied flows have no OS user id; a stable id per app keeps the per-app HTTPS bypass
    /// cache and logs apart. The high bit keeps it away from real Android/Unix uids.
    fn owner(&self) -> Owner {
        let hash = self.app.bytes().fold(0x811c_9dc5u32, |hash, byte| {
            (hash ^ byte as u32).wrapping_mul(0x0100_0193)
        });
        Owner {
            uid: Some(hash | 0x8000_0000),
            packages: vec![self.app.clone()],
            bypass: false,
            blocked: false,
        }
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_needs_the_token_and_all_fields() {
        let token = "00112233445566778899aabbccddeeff";
        assert_eq!(
            Request::parse(
                &format!("OAB1 {token} 93.184.216.34 443 com.google.Chrome\n"),
                token
            ),
            Some(Request {
                host: "93.184.216.34".into(),
                port: 443,
                app: "com.google.Chrome".into()
            })
        );
        assert_eq!(
            Request::parse(
                &format!("OAB1 {token} [2606:2800::1] 443 com.apple.Safari\r\n"),
                token
            )
            .map(|r| r.host),
            Some("2606:2800::1".into())
        );
        for bad in [
            "OAB1 wrong 1.2.3.4 443 app\n".to_owned(),
            format!("OAB2 {token} 1.2.3.4 443 app\n"),
            format!("OAB1 {token} 1.2.3.4 0 app\n"),
            format!("OAB1 {token} 1.2.3.4 443\n"),
            format!("OAB1 {token} 1.2.3.4 443 app extra\n"),
        ] {
            assert_eq!(Request::parse(&bad, token), None, "{bad}");
        }
    }

    #[test]
    fn app_ids_map_to_stable_high_uids() {
        let request = |app: &str| Request {
            host: "h".into(),
            port: 1,
            app: app.into(),
        };
        let chrome = request("com.google.Chrome").owner();
        assert_eq!(chrome.uid, request("com.google.Chrome").owner().uid);
        assert_ne!(chrome.uid, request("com.apple.Safari").owner().uid);
        assert!(chrome.uid.unwrap() & 0x8000_0000 != 0);
        assert_eq!(chrome.packages, ["com.google.Chrome"]);
    }
}
