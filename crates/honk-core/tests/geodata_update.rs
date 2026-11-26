//! An embedder drives geodata updates through the public `geodata_update`
//! API with its own transport, as the daemon's native API does with honk's.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use honk_core::geodata_update::{
    AutoUpdate, DEFAULT_URLS, Failure, Get, History, STARTUP_DELAY, Transport, fetch,
};

/// Answers each URL from a table; a URL missing from it is unreachable.
struct Table(HashMap<String, Result<Vec<u8>, Failure>>);

impl Table {
    fn new(entries: &[(&str, Result<&[u8], Failure>)]) -> Self {
        Self(
            entries
                .iter()
                .map(|(url, answer)| (url.to_string(), answer.map(<[u8]>::to_vec)))
                .collect(),
        )
    }
}

impl Transport for Table {
    type Via = ();

    async fn get(&self, get: Get<'_>) -> Result<(Arc<[u8]>, ()), Failure> {
        match self.0.get(get.url) {
            Some(Ok(body)) if body.len() <= get.max_bytes => Ok((body.as_slice().into(), ())),
            Some(Ok(_)) => Err("body_too_large".into()),
            Some(Err(failure)) => Err(*failure),
            None => Err("connect_failed".into()),
        }
    }
}

const NOT_FOUND: Failure = Failure {
    code: "http_not_found",
    status: Some(404),
};

fn sha256_line(body: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    let hex: String = sha2::Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{hex}  geosite.dat\n").into_bytes()
}

fn urls(list: &[&str]) -> Vec<String> {
    list.iter().map(|url| url.to_string()).collect()
}

#[tokio::test]
async fn a_mismatched_checksum_falls_back_to_the_next_url() {
    let good: &[u8] = b"good geosite";
    let checksum = sha256_line(good);
    let table = Table::new(&[
        ("https://a.example/geosite.dat", Ok(b"tampered")),
        ("https://a.example/geosite.dat.sha256sum", Ok(&checksum)),
        ("https://b.example/geosite.dat", Ok(good)),
        ("https://b.example/geosite.dat.sha256sum", Ok(&checksum)),
    ]);
    let (bytes, fetched) = fetch(
        &urls(&[
            "https://a.example/geosite.dat",
            "https://b.example/geosite.dat",
        ]),
        &table,
        1 << 20,
        true,
    )
    .await
    .unwrap();
    assert_eq!(&*bytes, good);
    assert_eq!(fetched.url, "https://b.example/geosite.dat");
    assert!(fetched.verified);
}

#[tokio::test]
async fn a_missing_checksum_accepts_the_file_unverified() {
    let table = Table::new(&[
        ("https://a.example/geosite.dat", Ok(b"geosite")),
        ("https://a.example/geosite.dat.sha256sum", Err(NOT_FOUND)),
    ]);
    let (_, fetched) = fetch(
        &urls(&["https://a.example/geosite.dat"]),
        &table,
        1 << 20,
        true,
    )
    .await
    .unwrap();
    assert!(!fetched.verified);
}

/// The pair bundled in the data root is the current generation: nothing has
/// to be downloaded before the engine starts, and a failed check leaves it in
/// place and only moves the schedule.
#[tokio::test]
async fn an_unreachable_origin_keeps_the_bundled_pair() {
    let root = tempfile::tempdir().unwrap();
    for name in ["geosite.dat", "geoip.dat"] {
        std::fs::write(root.path().join(name), format!("bundled {name}")).unwrap();
    }
    let now = SystemTime::now();
    let mut history = History::default();
    let (first, _) = history.next_check(&AutoUpdate::default(), now, &chrono::Local);
    assert!(first.unwrap() >= now + STARTUP_DELAY);

    let unreachable = Table::new(&[]);
    for urls in DEFAULT_URLS {
        let failure = fetch(&urls.map(str::to_owned), &unreachable, 1 << 20, true)
            .await
            .unwrap_err();
        assert_eq!(failure.code, "connect_failed");
        history.record(now, Err(failure.code.to_owned()));
    }
    for name in ["geosite.dat", "geoip.dat"] {
        assert_eq!(
            std::fs::read_to_string(root.path().join(name)).unwrap(),
            format!("bundled {name}")
        );
    }
    assert_eq!(history.failures, 2);
    let reopened = History::from_json(&history.to_json()).unwrap();
    assert_eq!(reopened.failures, 2);
    assert_eq!(reopened.last_error.as_deref(), Some("connect_failed"));
    // Two failures: at most a two-hour backoff, plus up to an hour of jitter.
    let (retry, _) = reopened.next_check(&AutoUpdate::default(), now, &chrono::Local);
    let wait = retry.unwrap().duration_since(now).unwrap();
    assert!(
        wait >= STARTUP_DELAY && wait <= Duration::from_secs(3 * 3600),
        "{wait:?}"
    );
}
