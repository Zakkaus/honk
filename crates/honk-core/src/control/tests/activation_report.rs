use super::support::control_plane;
use super::*;
use crate::config_diagnostics::{ActivationReport, DiagnosticUpdate, UnsupportedSetting};
use crate::subscription::SubscriptionAuthorizations;
use honk_config::parser::{LoadedConfig, SourceLimits, parse_dae_sources};

const MAIN: &str = "global {\n    # reloadable\n    check_tolerance: 100ms\n}\n";
const STAGING: &str = "# UDP staging\n\nglobal {\n      nfqueue_enable: true   # wanted\n}\n";

fn load(documents: &[(&str, &str)]) -> LoadedConfig {
    let inputs: Vec<_> = documents
        .iter()
        .map(|(path, content)| (std::path::PathBuf::from(path), Arc::from(*content)))
        .collect();
    parse_dae_sources(&inputs, SourceLimits::default(), &mut Vec::new()).unwrap()
}

/// NFQUEUE is unavailable to this process, as after a failed startup preflight.
async fn downgraded() -> ControlPlane {
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    let mut cp = control_plane(config);
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", ""),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();
    cp.startup_downgrades().record_nfqueue_unavailable();
    cp.install_startup_diagnostics(Default::default()).await;
    cp
}

async fn activate(cp: &ControlPlane, loaded: &LoadedConfig) -> ActivationReport {
    cp.reload_runtime_config_from_sources(
        loaded.config.clone(),
        Default::default(),
        &loaded.sources,
    )
    .await
    .expect("candidate is accepted")
}

/// One-based line and byte column, and the declaration text.
fn located<'a>(
    loaded: &'a LoadedConfig,
    setting: &UnsupportedSetting,
) -> (usize, usize, usize, &'a str) {
    let location = setting.location.as_ref().expect("declaration is located");
    (
        location.source_index,
        location.line,
        location.column,
        &loaded.sources[location.source_index].content[location.bytes.clone()],
    )
}

#[test]
fn downgrades_report_only_what_the_candidate_asks_for() {
    let downgrades = StartupDowngrades::default();
    let mut config = Config::default();
    config.global.nfqueue_enable = true;
    assert!(downgrades.unsupported(&config).is_empty());
    assert!(downgrades.unsupported_at_startup().is_empty());
    downgrades.record_nfqueue_unavailable();
    let unsupported = downgrades.unsupported(&config);
    assert_eq!(
        unsupported
            .iter()
            .map(|setting| (setting.code, setting.setting, setting.location.is_none()))
            .collect::<Vec<_>>(),
        [("nfqueue_unavailable", "global.nfqueue_enable", true)]
    );
    assert_eq!(downgrades.unsupported_at_startup(), unsupported);
    config.global.nfqueue_enable = false;
    assert!(downgrades.unsupported(&config).is_empty());
}

#[tokio::test]
async fn startup_reports_the_nfqueue_downgrade_without_a_location() {
    let cp = downgraded().await;
    let report = cp.activation_report();
    assert_eq!(report.generation, cp.diagnostics.read().generation);
    assert_eq!(
        report.unsupported,
        cp.startup_downgrades().unsupported_at_startup()
    );
    assert_eq!(report.unsupported.len(), 1);
}

#[tokio::test]
async fn activation_locates_unsupported_settings_in_the_user_config() {
    let cp = downgraded().await;
    let before = cp.activation_report();
    let loaded = load(&[("main.dae", MAIN), ("staging.dae", STAGING)]);
    assert!(loaded.config.global.nfqueue_enable);

    let report = activate(&cp, &loaded).await;
    assert!(report.generation > before.generation);
    assert_eq!(report, cp.activation_report());
    let [setting] = report.unsupported.as_slice() else {
        panic!("one unsupported setting: {report:?}");
    };
    assert_eq!(
        (setting.code, setting.setting),
        ("nfqueue_unavailable", "global.nfqueue_enable")
    );
    assert_eq!(located(&loaded, setting), (1, 4, 7, "nfqueue_enable: true"));
    // The downgrade itself is unchanged: the generation runs without NFQUEUE.
    let active = cp.config.read().await.clone();
    assert!(!active.global.nfqueue_enable);
    assert_eq!(active.global.check_tolerance_ms, 100);
}

#[tokio::test]
async fn the_report_follows_the_operator_document_of_each_generation() {
    let cp = downgraded().await;
    let first = activate(&cp, &load(&[("main.dae", MAIN), ("staging.dae", STAGING)])).await;

    // The same effective configuration is a no-op that keeps the generation,
    // yet the report points at the new declaration.
    let moved = load(&[
        ("main.dae", MAIN),
        ("other.dae", "global {\nnfqueue_enable: on\n}\n"),
    ]);
    let noop = activate(&cp, &moved).await;
    assert_eq!(noop.generation, first.generation);
    assert_eq!(
        located(&moved, &noop.unsupported[0]),
        (1, 2, 1, "nfqueue_enable: on")
    );
    assert_eq!(cp.activation_report(), noop);

    // A rejected candidate leaves the report alone.
    let mut restart_only = moved.config.clone();
    restart_only.global.log_level = "debug".into();
    assert!(
        cp.reload_runtime_config_from_sources(restart_only, Default::default(), &moved.sources)
            .await
            .is_none()
    );
    assert_eq!(cp.activation_report(), noop);

    // An update that keeps the operator document keeps its report.
    let mut refreshed = cp.config.read().await.as_ref().clone();
    refreshed.global.check_tolerance_ms += 1;
    let outcome = cp
        .apply_resolved_runtime_config_locked(
            refreshed,
            &DrainTracker::new(),
            DiagnosticUpdate::Preserve,
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    let kept = cp.activation_report();
    assert_eq!(Some(kept.generation), outcome.generation());
    assert!(kept.generation > noop.generation);
    assert_eq!(kept.unsupported, noop.unsupported);

    // A value left at its default has no declaration to point at.
    let unwritten = load(&[("main.dae", MAIN)]);
    let report = activate(&cp, &unwritten).await;
    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(report.unsupported[0].location, None);

    // A document that no longer asks for the setting clears the report.
    let off = load(&[
        ("main.dae", MAIN),
        ("off.dae", "global {\n nfqueue_enable: false\n}\n"),
    ]);
    let cleared = activate(&cp, &off).await;
    assert!(cleared.unsupported.is_empty());
    assert_eq!(cp.activation_report(), cleared);
}

#[tokio::test]
async fn sighup_reports_the_candidate_before_its_downgrade() {
    let cp = downgraded().await;
    let loaded = load(&[("main.dae", MAIN), ("staging.dae", STAGING)]);
    let current = cp.config.read().await;
    let mut authorizations = SubscriptionAuthorizations::new(&current.subscriptions).unwrap();
    drop(current);
    let outcome = cp
        .apply_sighup_config(
            loaded.config.clone(),
            Vec::new(),
            &DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    let report = cp.activation_report();
    assert_eq!(Some(report.generation), outcome.generation());
    assert_eq!(
        report
            .unsupported
            .iter()
            .map(|setting| (setting.setting, setting.location.is_none()))
            .collect::<Vec<_>>(),
        [("global.nfqueue_enable", true)]
    );
    assert!(!cp.config.read().await.global.nfqueue_enable);
}

#[tokio::test]
async fn a_failed_nfqueue_startup_publishes_the_report() {
    let mut config = Config::default();
    config.global.nfqueue_enable = true;
    let mut cp = control_plane(config);
    cp.install_startup_diagnostics(Default::default()).await;
    assert!(cp.activation_report().unsupported.is_empty());

    let mut enabled = true;
    cp.degrade_nfqueue_startup(&mut enabled, anyhow::anyhow!("injected startup failure"))
        .await;

    assert!(!enabled);
    assert!(!cp.config.read().await.global.nfqueue_enable);
    let report = cp.activation_report();
    assert_eq!(
        report.unsupported,
        cp.startup_downgrades().unsupported_at_startup()
    );
    assert_eq!(
        report
            .unsupported
            .iter()
            .map(|setting| (setting.setting, setting.location.is_none()))
            .collect::<Vec<_>>(),
        [("global.nfqueue_enable", true)]
    );
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn a_native_sighup_locates_unsupported_settings_in_its_sources() {
    let cp = downgraded().await;
    let loaded = load(&[("main.dae", MAIN), ("staging.dae", STAGING)]);
    let sources = crate::configuration::SourceUpdate {
        sources: loaded.sources.clone(),
        dependencies: Vec::new(),
        geo_sources: None,
    };
    let current = cp.config.read().await;
    let mut authorizations = SubscriptionAuthorizations::new(&current.subscriptions).unwrap();
    drop(current);
    let outcome = cp
        .apply_sighup_config(
            loaded.config.clone(),
            Vec::new(),
            &DrainTracker::new(),
            &mut authorizations,
            Some(&sources),
            None,
        )
        .await
        .unwrap();

    let report = cp.activation_report();
    assert_eq!(Some(report.generation), outcome.generation());
    let [setting] = report.unsupported.as_slice() else {
        panic!("one unsupported setting: {report:?}");
    };
    assert_eq!(located(&loaded, setting), (1, 4, 7, "nfqueue_enable: true"));
}
