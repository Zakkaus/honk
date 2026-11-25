//! Runtime data-directory path resolution shared by the engine and handlers.
//!
//! Generated state and relative runtime dependencies use the process-wide
//! directory selected from `global.data_dir`. Existing legacy paths remain
//! usable during upgrades.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default home for generated state and runtime-supplied assets.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/honk";

/// Previous default home retained for existing runtime state and assets.
pub const LEGACY_DATA_DIR: &str = "/var/share/honk";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Return the configured process-wide runtime data directory.
pub fn data_dir() -> &'static Path {
    DATA_DIR
        .get_or_init(|| PathBuf::from(DEFAULT_DATA_DIR))
        .as_path()
}

/// Install the process-wide runtime data directory.
///
/// Repeating the same value is idempotent. A different value is returned to
/// the caller because path ownership cannot change after runtime consumers
/// have started.
pub fn set_data_dir(path: impl Into<PathBuf>) -> Result<(), PathBuf> {
    let requested = path.into();
    if let Some(configured) = DATA_DIR.get() {
        return if configured == &requested {
            Ok(())
        } else {
            Err(requested)
        };
    }
    match DATA_DIR.set(requested) {
        Ok(()) => Ok(()),
        Err(requested) if DATA_DIR.get() == Some(&requested) => Ok(()),
        Err(requested) => Err(requested),
    }
}

/// Resolve an artifact path for creation or mutation.
///
/// An absolute configured path remains explicit. Every relative path is rooted
/// in the configured data directory so automatic state never depends on the
/// service's working directory.
pub fn resolve_artifact_path(path: impl AsRef<Path>) -> PathBuf {
    resolve_artifact_path_from(path.as_ref(), data_dir())
}

fn resolve_artifact_path_from(path: &Path, data_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        data_dir.join(path)
    }
}

/// Resolve a writable runtime artifact while retaining existing legacy
/// locations during upgrades.
///
/// Absolute paths remain explicit. For a relative path, an existing copy below
/// the configured data directory wins, followed by the previous default data
/// directory and then the caller-supplied legacy path. If none exists, the
/// returned path is below the configured data directory for new artifacts.
pub fn resolve_artifact_path_with_legacy(
    path: impl AsRef<Path>,
    legacy_path: Option<&Path>,
) -> PathBuf {
    resolve_path_with_legacy_from(
        path.as_ref(),
        data_dir(),
        Path::new(LEGACY_DATA_DIR),
        legacy_path,
    )
}

fn resolve_path_with_legacy_from(
    path: &Path,
    data_dir: &Path,
    legacy_data_dir: &Path,
    legacy_path: Option<&Path>,
) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    let preferred = data_dir.join(path);
    if preferred.exists() {
        return preferred;
    }

    let legacy_data_path = legacy_data_dir.join(path);
    if legacy_data_path.exists() {
        return legacy_data_path;
    }

    legacy_path
        .filter(|path| path.exists())
        .map_or(preferred, Path::to_path_buf)
}

/// Resolve a read-only runtime dependency.
///
/// Absolute paths remain explicit. For a relative path, an existing copy in
/// the configured data directory takes precedence, followed by the previous
/// default data directory and the current-working-directory path. A missing
/// path resolves to the configured data-directory location for clear errors
/// and future creation.
pub fn resolve_dependency_path(path: impl AsRef<Path>) -> PathBuf {
    resolve_dependency_path_from(path, data_dir())
}

/// Resolve a read-only dependency against an explicit effective data directory.
/// This does not install or modify the process-wide runtime directory.
pub fn resolve_dependency_path_from(path: impl AsRef<Path>, data_dir: &Path) -> PathBuf {
    let path = path.as_ref();
    resolve_path_with_legacy_from(path, data_dir, Path::new(LEGACY_DATA_DIR), Some(path))
}

/// Locations the daemon searches for a geo asset after its data directory.
const DAEMON_ASSET_FALLBACKS: [&str; 7] = [
    LEGACY_DATA_DIR,
    ".",
    "/usr/local/share/honk",
    "/usr/share/honk",
    "/usr/local/share/dae",
    "/usr/share/dae",
    "/etc/dae",
];

/// Where one engine keeps generated state and finds runtime assets.
///
/// The daemon root keeps every legacy and system location in its search
/// order. An explicit root, for an engine embedded in another process,
/// resolves every relative path only below its own directory: it ignores
/// `$DAE_LOCATION_ASSET`, the old data directory, the working directory and the
/// honk and dae share directories. Absolute paths a configuration names stay
/// as written under either root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRoot(Root);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Root {
    /// Read at each use, so holding it never fixes the process directory early.
    Process,
    Daemon(PathBuf),
    Explicit(PathBuf),
}

impl DataRoot {
    /// A daemon root with the documented legacy and system search order.
    pub fn daemon(dir: impl Into<PathBuf>) -> Self {
        Self(Root::Daemon(dir.into()))
    }

    /// A root that resolves relative paths only below `dir`, which should be
    /// absolute: a relative `dir` itself depends on the working directory.
    pub fn explicit(dir: impl Into<PathBuf>) -> Self {
        Self(Root::Explicit(dir.into()))
    }

    /// The daemon root installed for this process by [`set_data_dir`],
    /// read when used.
    pub fn process() -> Self {
        Self(Root::Process)
    }

    pub fn dir(&self) -> &Path {
        match &self.0 {
            Root::Process => data_dir(),
            Root::Daemon(dir) | Root::Explicit(dir) => dir,
        }
    }

    /// Whether this root also searches legacy and system locations.
    pub fn searches_system_locations(&self) -> bool {
        !matches!(self.0, Root::Explicit(_))
    }

    /// The `$DAE_LOCATION_ASSET` override, honoured only by a daemon root.
    pub fn asset_override(&self) -> Option<PathBuf> {
        self.asset_override_from(std::env::var_os("DAE_LOCATION_ASSET"))
    }

    fn asset_override_from(&self, value: Option<std::ffi::OsString>) -> Option<PathBuf> {
        value
            .filter(|_| self.searches_system_locations())
            .map(PathBuf::from)
    }

    /// Resolve an artifact path for creation or mutation; see
    /// [`resolve_artifact_path`].
    pub fn resolve_artifact(&self, path: impl AsRef<Path>) -> PathBuf {
        resolve_artifact_path_from(path.as_ref(), self.dir())
    }

    /// Resolve a writable artifact; see
    /// [`resolve_artifact_path_with_legacy`]. An explicit root never falls
    /// back to a legacy location.
    pub fn resolve_artifact_with_legacy(
        &self,
        path: impl AsRef<Path>,
        legacy_path: Option<&Path>,
    ) -> PathBuf {
        if self.searches_system_locations() {
            resolve_path_with_legacy_from(
                path.as_ref(),
                self.dir(),
                Path::new(LEGACY_DATA_DIR),
                legacy_path,
            )
        } else {
            self.resolve_artifact(path)
        }
    }

    /// Resolve a read-only dependency; see [`resolve_dependency_path`]. An
    /// explicit root never falls back to the old data directory or the
    /// working directory.
    pub fn resolve_dependency(&self, path: impl AsRef<Path>) -> PathBuf {
        if self.searches_system_locations() {
            resolve_dependency_path_from(path, self.dir())
        } else {
            self.resolve_artifact(path)
        }
    }

    /// Locate a geo asset such as `geosite.dat`, selecting only regular files.
    ///
    /// A daemon root searches `$DAE_LOCATION_ASSET`, its directory, the old
    /// data directory, the working directory, the honk share directories and
    /// then dae's locations. An explicit root searches only its directory.
    pub fn find_asset(&self, name: &str) -> Option<PathBuf> {
        // The asset search has always ignored a non-UTF-8 value.
        self.find_asset_from(
            name,
            std::env::var("DAE_LOCATION_ASSET").ok().map(Into::into),
            &DAEMON_ASSET_FALLBACKS.map(Path::new),
        )
    }

    fn find_asset_from(
        &self,
        name: &str,
        asset_override: Option<std::ffi::OsString>,
        daemon_fallbacks: &[&Path],
    ) -> Option<PathBuf> {
        let fallbacks = if self.searches_system_locations() {
            daemon_fallbacks
        } else {
            &[]
        };
        self.asset_override_from(asset_override)
            .into_iter()
            .chain([self.dir().to_path_buf()])
            .chain(fallbacks.iter().map(|directory| directory.to_path_buf()))
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifacts_honor_a_custom_data_directory() {
        assert_eq!(
            resolve_artifact_path_from(Path::new("cache.db"), Path::new("/srv/honk")),
            PathBuf::from("/srv/honk/cache.db")
        );
    }

    #[test]
    fn absolute_paths_stay_explicit() {
        assert_eq!(
            resolve_artifact_path("/srv/honk/cache.db"),
            PathBuf::from("/srv/honk/cache.db")
        );
        assert_eq!(
            resolve_dependency_path("/srv/honk/ech.txt"),
            PathBuf::from("/srv/honk/ech.txt")
        );
    }

    #[test]
    fn legacy_resolution_prefers_configured_then_old_root_then_caller() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let legacy_data_dir = temp.path().join("old");
        let caller_dir = temp.path().join("cwd");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&legacy_data_dir).unwrap();
        std::fs::create_dir_all(&caller_dir).unwrap();

        let relative = Path::new("asset.dat");
        let caller_path = caller_dir.join(relative);
        std::fs::write(&caller_path, "caller").unwrap();
        let resolve = || {
            resolve_path_with_legacy_from(relative, &data_dir, &legacy_data_dir, Some(&caller_path))
        };

        assert_eq!(resolve(), caller_path);
        std::fs::write(legacy_data_dir.join(relative), "old").unwrap();
        let chosen = resolve();
        assert_eq!(std::fs::read_to_string(&chosen).unwrap(), "old");

        std::fs::write(data_dir.join(relative), "new").unwrap();
        let chosen = resolve();
        assert_eq!(std::fs::read_to_string(&chosen).unwrap(), "new");

        std::fs::remove_file(data_dir.join(relative)).unwrap();
        std::fs::remove_file(legacy_data_dir.join(relative)).unwrap();
        assert_eq!(resolve(), caller_path);
        std::fs::remove_file(&caller_path).unwrap();
        assert_eq!(resolve(), data_dir.join(relative));

        let absolute = temp.path().join("explicit.dat");
        assert_eq!(
            resolve_path_with_legacy_from(
                &absolute,
                &data_dir,
                &legacy_data_dir,
                Some(&caller_path),
            ),
            absolute
        );

        let sub = Path::new(".sub");
        let old_sub = legacy_data_dir.join(sub);
        std::fs::create_dir_all(&old_sub).unwrap();
        assert_eq!(
            resolve_path_with_legacy_from(
                sub,
                &data_dir,
                &legacy_data_dir,
                Some(&caller_dir.join(sub)),
            ),
            old_sub
        );
    }

    #[test]
    fn explicit_root_ignores_override_legacy_and_system_locations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("geosite.dat"), "x").unwrap();
        std::fs::write(elsewhere.join("hosts"), "x").unwrap();

        let explicit = DataRoot::explicit(&root);
        assert!(!explicit.searches_system_locations());
        assert_eq!(
            explicit.asset_override_from(Some(elsewhere.clone().into_os_string())),
            None
        );
        assert_eq!(
            explicit.find_asset_from(
                "geosite.dat",
                Some(elsewhere.clone().into_os_string()),
                &[elsewhere.as_path()]
            ),
            None
        );
        assert_eq!(
            explicit.resolve_dependency("hosts"),
            root.join("hosts"),
            "a missing dependency stays below the explicit root"
        );
        assert_eq!(
            explicit.resolve_artifact_with_legacy("hosts", Some(&elsewhere.join("hosts"))),
            root.join("hosts")
        );

        std::fs::write(root.join("geosite.dat"), "y").unwrap();
        assert_eq!(
            explicit.find_asset_from(
                "geosite.dat",
                Some(elsewhere.clone().into_os_string()),
                &[elsewhere.as_path()]
            ),
            Some(root.join("geosite.dat"))
        );
        assert_eq!(
            DataRoot::explicit("/srv/a").resolve_dependency("/etc/hosts"),
            PathBuf::from("/etc/hosts")
        );
    }

    #[test]
    fn daemon_root_keeps_the_documented_asset_order() {
        let temp = tempfile::tempdir().unwrap();
        let [env, root, legacy, share] =
            ["env", "root", "legacy", "share"].map(|name| temp.path().join(name));
        for directory in [&env, &root, &legacy, &share] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let daemon = DataRoot::daemon(&root);
        let fallbacks = [legacy.as_path(), share.as_path()];
        let find = || daemon.find_asset_from("geoip.dat", Some(env.clone().into()), &fallbacks);

        assert_eq!(find(), None);
        for directory in [&share, &legacy, &root, &env] {
            std::fs::write(directory.join("geoip.dat"), "x").unwrap();
            assert_eq!(find(), Some(directory.join("geoip.dat")));
        }
        std::fs::remove_file(env.join("geoip.dat")).unwrap();
        std::fs::create_dir(env.join("geoip.dat")).unwrap();
        assert_eq!(
            find(),
            Some(root.join("geoip.dat")),
            "only regular files count"
        );

        assert_eq!(
            daemon.asset_override_from(Some(env.clone().into_os_string())),
            Some(env)
        );
        assert_eq!(DataRoot::process().dir(), data_dir());
        assert_eq!(
            DAEMON_ASSET_FALLBACKS,
            [
                "/var/share/honk",
                ".",
                "/usr/local/share/honk",
                "/usr/share/honk",
                "/usr/local/share/dae",
                "/usr/share/dae",
                "/etc/dae",
            ]
        );
    }
}
