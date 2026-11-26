//! Geodata updates without the native API or the state database: the
//! built-in sources, the automatic schedule with its backoff after failures,
//! and the checksum-checked download. The daemon's native API runs on the
//! same code; an embedder supplies the transport and keeps the history.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, TimeZone, Utc};
use honk_config::cron::Cron;

mod fetch;

pub use fetch::{
    CHECKSUM_TIMEOUT, DOWNLOAD_LIMIT, Failure, Fetched, Get, IDLE_TIMEOUT, Transport, fetch,
};

/// The assets an update replaces, in the order every per-asset list uses.
pub const KINDS: [&str; 2] = ["geosite", "geoip"];
/// The most URLs one asset may list.
pub const MAX_URLS: usize = 4;
/// The hours an interval schedule may wait between checks.
pub const INTERVAL_HOURS: std::ops::RangeInclusive<u64> = 6..=168;
/// What `interval_hours` reads under a cron schedule, so a client that knows
/// only intervals still shows a day.
pub const NOMINAL_INTERVAL_HOURS: u64 = 24;
const DEFAULT_CRON: &str = "0 3 * * *";
/// The longest random delay added to a scheduled check.
pub const MAX_JITTER_SECS: u64 = 3600;
/// The wait after the first failed check; each further failure doubles it.
pub const FIRST_BACKOFF: Duration = Duration::from_secs(3600);
/// The shortest wait before an automatic check, so a startup never downloads
/// at once, however long ago the last check was.
pub const STARTUP_DELAY: Duration = Duration::from_secs(300);
/// Each asset's URLs in fallback order: MetaCubeX full, raw first; jsDelivr
/// serves the same bytes where GitHub is slow.
pub const DEFAULT_URLS: [[&str; 2]; 2] = [
    [
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat",
        "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    ],
    [
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat",
        "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    ],
];

/// Whether geodata is checked automatically, and when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoUpdate {
    pub enabled: bool,
    pub schedule: Schedule,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// At each time the expression names in the system's local time.
    Cron(Cron),
    /// Every so many hours after the last check, as records written before
    /// cron schedules existed keep doing.
    Interval(u64),
}

impl Default for AutoUpdate {
    fn default() -> Self {
        Self {
            enabled: true,
            schedule: Schedule::Cron(Cron::parse(DEFAULT_CRON).expect("the default cron parses")),
        }
    }
}

/// A cron schedule with no future occurrence in the time zone.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "geodata cron has no future occurrence in the system time zone; change or disable the schedule"
)]
pub struct ScheduleUnavailable;

/// Refuses a cron schedule that never fires again in `zone`.
pub fn validate_schedule<Tz: TimeZone>(
    schedule: &Schedule,
    now: SystemTime,
    zone: &Tz,
) -> Result<(), ScheduleUnavailable> {
    if let Schedule::Cron(cron) = schedule
        && cron.next_after(DateTime::<Utc>::from(now), zone).is_none()
    {
        return Err(ScheduleUnavailable);
    }
    Ok(())
}

/// The next check before jitter, and whether the cron has no future local
/// occurrence. Counts from the persisted last check; failure backoff can come
/// first or remain available without a cron occurrence. Unknown, future or
/// overdue checks wait at least `STARTUP_DELAY` to avoid immediate downloads
/// at every startup.
pub fn due<Tz: TimeZone>(
    schedule: &Schedule,
    last_checked: Option<SystemTime>,
    failures: u32,
    now: SystemTime,
    zone: &Tz,
) -> (Option<SystemTime>, bool) {
    let checked = last_checked.filter(|checked| *checked <= now);
    let reference = checked.unwrap_or(now);
    let scheduled = match schedule {
        Schedule::Interval(hours) => Some(reference + Duration::from_secs(hours * 3600)),
        Schedule::Cron(cron) => cron
            .next_after(DateTime::<Utc>::from(reference), zone)
            .map(SystemTime::from),
    };
    let unavailable = scheduled.is_none();
    let next = match checked {
        None => Some(now),
        Some(checked) => {
            let retry = (failures > 0)
                .then(|| checked + FIRST_BACKOFF.saturating_mul(1 << (failures - 1).min(16)));
            match (scheduled, retry) {
                (Some(scheduled), Some(retry)) => Some(scheduled.min(retry)),
                (next, None) | (None, next) => next,
            }
        }
    };
    (next.map(|due| due.max(now + STARTUP_DELAY)), unavailable)
}

/// Up to an hour, so many devices on the same schedule do not download at once.
pub fn jitter() -> Duration {
    Duration::from_secs(rand::random_range(0..=MAX_JITTER_SECS))
}

/// The outcome of past checks, which the caller keeps across restarts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    pub last_checked_at: Option<SystemTime>,
    /// The last check that replaced a loaded file.
    pub last_updated_at: Option<SystemTime>,
    /// The failure code of the last check, None after a success.
    pub last_error: Option<String>,
    /// Failed checks since the last success; each one doubles the backoff.
    pub failures: u32,
}

impl History {
    /// Records a check that finished at `now`: `Ok(replaced)`, with `replaced`
    /// when it changed a loaded file, or `Err(code)`.
    pub fn record(&mut self, now: SystemTime, outcome: Result<bool, String>) {
        self.last_checked_at = Some(now);
        match outcome {
            Ok(replaced) => {
                self.failures = 0;
                self.last_error = None;
                if replaced {
                    self.last_updated_at = Some(now);
                }
            }
            Err(code) => {
                self.failures = self.failures.saturating_add(1);
                self.last_error = Some(code);
            }
        }
    }

    /// When the next automatic check is due, jitter included, or None while
    /// `auto` is disabled; and whether the cron has no future occurrence in
    /// `zone`. A history that was never checked is due after `STARTUP_DELAY`.
    pub fn next_check<Tz: TimeZone>(
        &self,
        auto: &AutoUpdate,
        now: SystemTime,
        zone: &Tz,
    ) -> (Option<SystemTime>, bool) {
        if !auto.enabled {
            return (None, false);
        }
        let (next, unavailable) = due(
            &auto.schedule,
            self.last_checked_at,
            self.failures,
            now,
            zone,
        );
        (next.map(|due| due + jitter()), unavailable)
    }

    /// The history as JSON, times in whole seconds since the Unix epoch: the
    /// record the daemon keeps in its state database.
    pub fn to_json(&self) -> String {
        let secs = |time: SystemTime| {
            time.duration_since(UNIX_EPOCH)
                .ok()
                .map(|elapsed| elapsed.as_secs())
        };
        serde_json::to_string(&StoredHistory {
            last_checked_at: self.last_checked_at.and_then(secs),
            last_updated_at: self.last_updated_at.and_then(secs),
            last_error: self.last_error.clone(),
            failures: self.failures,
        })
        .expect("a history serializes")
    }

    /// Reads what `to_json` wrote; None when the text is not such a record.
    pub fn from_json(text: &str) -> Option<Self> {
        let stored = serde_json::from_str::<StoredHistory>(text).ok()?;
        let time = |secs: u64| UNIX_EPOCH.checked_add(Duration::from_secs(secs));
        Some(Self {
            last_checked_at: stored.last_checked_at.and_then(time),
            last_updated_at: stored.last_updated_at.and_then(time),
            last_error: stored.last_error,
            failures: stored.failures,
        })
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct StoredHistory {
    last_checked_at: Option<u64>,
    last_updated_at: Option<u64>,
    last_error: Option<String>,
    failures: u32,
}
