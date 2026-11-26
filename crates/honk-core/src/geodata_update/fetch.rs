//! The download of one asset: its URLs in fallback order, each checked
//! against the sha256 published beside it.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use honk_config::experimental::parse_geodata_url;
use tokio::time::Instant;

/// How long a file download may wait for any progress: the setup up to the
/// answer's headers, and then each wait for more of the body.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a file download may take in all, so a trickle cannot hold the
/// update forever.
pub const DOWNLOAD_LIMIT: Duration = Duration::from_secs(600);
/// The checksum request gets its own deadline instead of whatever a slow file
/// download left. It covers the whole request: a fresh route decision,
/// resolution, the tunnel, TLS and a body of at most `MAX_CHECKSUM_BYTES`.
pub const CHECKSUM_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CHECKSUM_BYTES: usize = 1024;

/// Why a URL failed: the stage code, and the status of a rejected HTTP reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub code: &'static str,
    pub status: Option<u16>,
}

impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self { code, status: None }
    }
}

/// One GET for [`fetch`].
#[derive(Debug, Clone, Copy)]
pub struct Get<'a> {
    pub url: &'a str,
    /// When the answer's headers must have arrived.
    pub headers_by: Instant,
    /// The longest wait for more of the body, and when all of it must have
    /// arrived; None when `headers_by` covers the whole request.
    pub idle: Option<(Duration, Instant)>,
    /// The largest body accepted.
    pub max_bytes: usize,
}

/// How [`fetch`] reaches its URLs.
pub trait Transport {
    /// What the transport reports about the way a request went, such as the
    /// group it went through.
    type Via;

    /// The body of a 200 answer. Another status fails with its stage code
    /// and the status; `http_not_found` for a 404 makes a missing checksum
    /// acceptable. A URL that does not parse fails with `invalid_source`.
    fn get(
        &self,
        get: Get<'_>,
    ) -> impl Future<Output = Result<(Arc<[u8]>, Self::Via), Failure>> + Send;
}

/// The file [`fetch`] accepted.
#[derive(Debug, Clone)]
pub struct Fetched<V> {
    pub url: String,
    pub sha256: String,
    /// Whether the published sha256 matched; false when none was published or
    /// none was asked for.
    pub verified: bool,
    /// How the file's request went.
    pub via: V,
}

/// Downloads an asset from the first URL that yields a usable file. A URL is
/// skipped on any download failure, and when fetching the sha256 published
/// beside it fails with anything but a 404 or the digest does not match; the
/// error of the last URL tried is returned. The file fails when it makes no
/// progress for `IDLE_TIMEOUT` or takes longer than `DOWNLOAD_LIMIT`, and its
/// checksum has a separate `CHECKSUM_TIMEOUT` that starts after the file
/// arrives. Without `verify_checksum` no checksum is requested and every
/// downloaded file is accepted unverified. Nothing is written: the caller
/// decides where the bytes go.
pub async fn fetch<T: Transport + Sync>(
    urls: &[String],
    transport: &T,
    max_bytes: usize,
    verify_checksum: bool,
) -> Result<(Arc<[u8]>, Fetched<T::Via>), Failure> {
    let mut last = Failure::from("invalid_source");
    for url in urls {
        let started = Instant::now();
        let file = Get {
            url,
            headers_by: started + IDLE_TIMEOUT,
            idle: Some((IDLE_TIMEOUT, started + DOWNLOAD_LIMIT)),
            max_bytes,
        };
        let (bytes, via) = match transport.get(file).await {
            Ok(downloaded) => downloaded,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let sha256 = crate::configuration::digest(&bytes);
        let verified = if verify_checksum {
            let Some(mut checksum) = parse_geodata_url(url) else {
                last = "invalid_source".into();
                continue;
            };
            checksum.set_path(&format!("{}.sha256sum", checksum.path()));
            let published = transport
                .get(Get {
                    url: checksum.as_str(),
                    headers_by: Instant::now() + CHECKSUM_TIMEOUT,
                    idle: None,
                    max_bytes: MAX_CHECKSUM_BYTES,
                })
                .await;
            match published {
                Ok((published, _)) => {
                    let matches = std::str::from_utf8(&published)
                        .ok()
                        .and_then(|text| text.split_whitespace().next())
                        .is_some_and(|expected| expected.eq_ignore_ascii_case(&sha256));
                    if !matches {
                        last = "checksum_mismatch".into();
                        continue;
                    }
                    true
                }
                Err(Failure {
                    code: "http_not_found",
                    ..
                }) => false,
                Err(error) => {
                    last = Failure {
                        code: "checksum_unavailable",
                        status: error.status,
                    };
                    continue;
                }
            }
        } else {
            false
        };
        return Ok((
            bytes,
            Fetched {
                url: url.clone(),
                sha256,
                verified,
                via,
            },
        ));
    }
    Err(last)
}
