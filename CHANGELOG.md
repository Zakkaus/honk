# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Entries live in [changes/](changes/) until release.

## [0.1.0-beta.3] - 2026-10-27

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.3), which list every change. Interface and VLAN handling changed for existing configurations: see the [migration guide](doc/migration/en/v0.1.0-beta.3.md).

### Changed

- honk plans and owns interface hooks per interface index, with type-aware framing and lazy reconciliation. (#352, #353)
- A missing or late interface no longer aborts startup, and TCX links follow device deletion and recreation. (#353)
- Per-device sysctl paths and the `interface_binding` degradation report interface setup failures explicitly.

### Fixed

- Bond interception and replies stay on the logical master, so active-backup failover keeps working while LAN bridge ports remain covered. (#354)
- VLAN-tagged and unsupported frames go to their own upper device. To manage a VLAN subnet, list the VLAN subinterface (for example `eth1.20`); a parent-only configuration no longer black-holes that subnet. (#355)

## [0.1.0-beta.2] - 2026-10-25

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.2), which list every change.

### Changed

- The per-source UDP new-flow budget is 1024/s per CPU.
- The UDP endpoint pool scales with RAM: a quarter of `MemTotal` at 64 KiB per endpoint, capped at 32,768.
- The 64 KiB UDP receive buffers moved out of endpoint and source task futures, cutting per-source and per-destination memory.
- BBRv3 is the default BBR for QUIC, and direct QUIC dials bind fresh sockets to recover from carrier loss.

### Fixed

- All client sources share one reply-socket pool per peer, so more than seven foreign peers no longer kill an ordinary full-cone endpoint or drop replies; flows that end by themselves are no longer fenced.

## [0.1.0-beta.1] - 2026-10-23

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.1), which list every change. Configuration moved since `v0.0.1.beta.84`: see the [migration guide](doc/migration/en/v0.1.0-beta.1.md).

### Added

- The opt-in native API (`native-api`) serves authenticated HTTP and SSE over runtime, sources, DNS, probes and lifecycle, and `native-ui` embeds the web UI. The Clash API remains the default.

### Changed

- AnyTLS uses eight carriers per node, a 1 MiB per-session write budget and single-copy frame serialization, raising upload throughput and lowering CPU and new-stream latency.
- Release archives are split by API (`full`, `clash-api`, `native-api`) and ship with `SHA256SUMS` and build provenance.
- Runtime state lives in `<data_dir>/state/honk.db`, `cache_file.enabled` changed meaning, and download defaults moved to the new `assets` block.

### Fixed

- A cancelled AnyTLS write no longer sends a payload the caller never accepted, and a spread re-election no longer fails a healthy pool or trips its dial breaker.
- OpenWrt kernels start from their external BTF.
- Shared UDP sources survive malformed SOCKS5, Trojan and Juicity datagrams.
- QUIC session tickets honour `skip_cert_verify`, and a reload restores warm carriers and probes.

[Unreleased]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.3...HEAD
[0.1.0-beta.3]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/daeuniverse/honk/compare/v0.0.1.beta.84...v0.1.0-beta.1
