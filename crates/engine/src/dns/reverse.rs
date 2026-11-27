//! Conservative, per-UID IP attribution. Shared IPs become ambiguous rather than guessed.
//! With the policy's `systemResolver` all owners share one table (see `policy::Options`).
use hickory_resolver::proto::{op::Message, rr::RData};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
struct Entry {
    domain: String,
    expires: Instant,
    ambiguous: bool,
}
type Entries = HashMap<(Option<u32>, IpAddr), Entry>;
static ENTRIES: OnceLock<Mutex<Entries>> = OnceLock::new();
pub fn clear() {
    ENTRIES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}
/// The table an owner's answers live in: its own, or the shared one under a system resolver.
fn scope(uid: Option<u32>) -> Option<u32> {
    if crate::policy::current().system_resolver {
        None
    } else {
        uid
    }
}
pub fn remember(uid: Option<u32>, domain: &str, response: &Message) {
    let uid = scope(uid);
    let mut entries = ENTRIES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if entries.len() >= 4096 {
        entries.retain(|_, e| e.expires > now);
    }
    for record in &response.answers {
        let ip = match &record.data {
            RData::A(ip) => IpAddr::V4(ip.0),
            RData::AAAA(ip) => IpAddr::V6(ip.0),
            _ => continue,
        };
        if record.ttl == 0 || ip.is_unspecified() {
            continue;
        }
        let expires = now + Duration::from_secs(record.ttl as u64);
        let key = (uid, ip);
        if let Some(entry) = entries.get_mut(&key).filter(|e| e.expires > now) {
            entry.ambiguous |= entry.domain != domain;
            entry.expires = entry.expires.max(expires);
        } else if entries.len() < 4096 {
            entries.insert(
                key,
                Entry {
                    domain: domain.to_owned(),
                    expires,
                    ambiguous: false,
                },
            );
        }
    }
}
pub fn lookup(uid: Option<u32>, ip: IpAddr) -> Option<String> {
    let uid = scope(uid);
    ENTRIES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(uid, ip))
        .filter(|e| !e.ambiguous && e.expires > Instant::now())
        .map(|e| e.domain.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::{rdata::A, Name, RData, Record};
    use std::net::Ipv4Addr;

    fn answer(ip: Ipv4Addr) -> Message {
        let mut message = Message::query();
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            60,
            RData::A(A(ip)),
        ));
        message
    }

    // One test so the global policy is not flipped under a parallel one.
    #[test]
    fn owners_share_answers_only_under_a_system_resolver() {
        let per_owner = Ipv4Addr::new(198, 51, 100, 71);
        crate::policy::configure("{}");
        remember(None, "example.test", &answer(per_owner));
        assert_eq!(
            lookup(None, per_owner.into()).as_deref(),
            Some("example.test")
        );
        assert_eq!(lookup(Some(42), per_owner.into()), None);

        let shared = Ipv4Addr::new(198, 51, 100, 72);
        crate::policy::configure(r#"{"systemResolver":true}"#);
        remember(None, "example.test", &answer(shared));
        assert_eq!(
            lookup(Some(42), shared.into()).as_deref(),
            Some("example.test")
        );
        crate::policy::configure("{}");
    }
}
