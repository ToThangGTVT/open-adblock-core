//! The binding-facing facade: packet-mode tunnel (macOS/Windows hosts), lifecycle errors and the
//! host-held CA signer.
use openadblock_engine::api::{
    self, ExternalSigner, SocketProtector, StartError, TunnelPacketSink,
};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use std::{
    io,
    net::UdpSocket,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

struct Allow;
impl SocketProtector for Allow {
    fn protect(&self, _: i32) -> io::Result<()> {
        Ok(())
    }
}
struct Collect(Mutex<mpsc::Sender<Vec<u8>>>);
impl TunnelPacketSink for Collect {
    fn packet(&self, packet: &[u8]) {
        let _ = self.0.lock().unwrap().send(packet.to_vec());
    }
}

fn udp(source: u16, destination: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![];
    etherparse::PacketBuilder::ipv4([172, 19, 0, 1], [127, 0, 0, 1], 64)
        .udp(source, destination)
        .write(&mut bytes, data)
        .unwrap();
    bytes
}

#[test]
fn packet_mode_relays_udp_reports_counters_and_stops() {
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    echo.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = echo.recv_from(&mut buffer) {
            let _ = echo.send_to(&buffer[..len], from);
        }
    });

    let (tx, rx) = mpsc::channel();
    let sink = Arc::new(Collect(Mutex::new(tx)));
    api::start_packets(Arc::new(Allow), None, sink.clone()).unwrap();
    assert!(api::is_running());
    assert!(matches!(
        api::start_packets(Arc::new(Allow), None, sink),
        Err(StartError::AlreadyRunning)
    ));

    let request = udp(40000, port, b"ping over packet mode");
    assert!(api::send_packet(&request));
    let deadline = Instant::now() + Duration::from_secs(5);
    let reply = loop {
        let packet = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("engine never answered through the packet sink");
        let Ok(sliced) = etherparse::SlicedPacket::from_ip(&packet) else {
            continue;
        };
        if let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport {
            if udp.source_port() == port && udp.destination_port() == 40000 {
                break udp.payload().to_vec();
            }
        }
    };
    assert_eq!(reply, b"ping over packet mode");
    let counters = api::counters();
    assert!(counters[0] >= 1, "packets_in {counters:?}");
    assert!(counters[1] >= 1, "packets_out {counters:?}");
    assert!(counters[3] >= 1, "udp_opened {counters:?}");

    api::stop();
    assert!(!api::is_running());
    assert!(!api::send_packet(&request));
    assert_eq!(api::counters(), [0; 8]);
    api::stop();
}

#[test]
fn dns_addresses_parse_like_the_android_link_properties_give_them() {
    assert_eq!(api::parse_dns("8.8.8.8"), Some("8.8.8.8".parse().unwrap()));
    assert_eq!(
        api::parse_dns("fe80::1%wlan0"),
        Some("fe80::1".parse().unwrap())
    );
    assert_eq!(api::parse_dns(""), None);
    assert_eq!(api::parse_dns("dns.google"), None);
}

#[test]
fn rule_reports_are_json() {
    let report: serde_json::Value =
        serde_json::from_str(&api::replace_rules("||ads.example^", "", "", false)).unwrap();
    assert_eq!(report["loaded"], 1);
}

#[test]
fn host_held_key_creates_and_installs_a_root_ca() {
    let random = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key = Arc::new(
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random).unwrap(),
    );
    let point = key.public_key().as_ref().to_vec();
    let signer_for = |key: Arc<EcdsaKeyPair>| {
        ExternalSigner::shared(point.clone(), move |data| {
            key.sign(&SystemRandom::new(), data)
                .ok()
                .map(|signature| signature.as_ref().to_vec())
        })
        .unwrap()
    };

    assert!(ExternalSigner::shared(vec![4; 64], |_| None).is_none());
    assert!(ExternalSigner::shared(vec![3; 65], |_| None).is_none());

    let der = api::generate_ca(signer_for(key.clone())).expect("root CA");
    assert!(api::set_ca(Some((signer_for(key), der.clone()))));
    let refusing = ExternalSigner::shared(point.clone(), |_| None).unwrap();
    assert!(api::generate_ca(refusing).is_none());
    assert!(api::set_ca(None));
}
