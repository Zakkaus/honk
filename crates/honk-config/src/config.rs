mod seed;
pub(crate) use seed::CONFIG_FIELDS;
pub use seed::ConfigSeed;
use seed::RawConfigSeed;

use std::ops::Range;

use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SettingPath, SourceRef, finish_attempt,
    report_detailed_diagnostics,
};
use crate::error::{DetailedConfigError, ErrorCategory};
use serde::de::DeserializeSeed;
use serde::{Deserialize, Serialize};
use serde_path_to_error::{Deserializer as PathDeserializer, Segment, Track};

use crate::ConfigDiagnostic;
use crate::dns::DnsConfig;
use crate::experimental::ExperimentalConfig;
use crate::group::Group;
use crate::node::Node;
use crate::routing::RoutingConfig;
use crate::subscription::Subscription;
use crate::types::DialMode;

/// Stable identity of the built-in `direct` node across reloads and restarts.
pub const DIRECT_NODE_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0x00000000_0000_4000_8000_00000000d1ec);
/// Stable identity of the built-in `block` node across reloads and restarts.
pub const BLOCK_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_4000_8000_00000000b10c);

/// `preconnect_node_count` sentinel for the dae `'auto'` value: preconnect
/// `min(nodes, 8)` nodes. Kept as a `usize` sentinel so the serde formats
/// stay plain integers; `0` means disabled.
pub const PRECONNECT_NODE_COUNT_AUTO: usize = usize::MAX;

/// Main honk configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub experimental: ExperimentalConfig,
}

/// Global configuration matching dae `global { ... }` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_tproxy_port")]
    pub tproxy_port: u16,
    #[serde(default = "default_tproxy_mark")]
    pub tproxy_mark: u32,
    #[serde(default = "crate::types::default_true")]
    pub tproxy_port_protect: bool,
    #[serde(default)]
    pub pprof_port: u16,
    #[serde(default)]
    pub so_mark_from_dae: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Optional append-only operational log file. Relative paths resolve below
    /// [`GlobalConfig::data_dir`]; empty keeps file logging disabled.
    #[serde(default)]
    pub log_file: String,
    #[serde(default)]
    pub disable_waiting_network: bool,
    #[serde(default)]
    pub lan_interface: Vec<String>,
    #[serde(default)]
    pub wan_interface: Vec<String>,
    #[serde(default)]
    pub auto_config_kernel_parameter: bool,
    /// Enable held-first-packet NFQUEUE staging for ambiguous LAN-forwarded UDP.
    /// This process-scoped setting requires the real eBPF backend and a restart.
    #[serde(default = "crate::types::default_true")]
    pub nfqueue_enable: bool,
    /// Root for generated state and relative runtime-supplied assets.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Persist successfully fetched subscription bodies below the configured
    /// runtime data directory so startup can recover without the network.
    #[serde(default = "default_store_subscribe")]
    pub store_subscribe: bool,
    #[serde(default = "default_tcp_check_urls")]
    pub tcp_check_url: Vec<String>,
    #[serde(default = "default_tcp_check_http_method")]
    pub tcp_check_http_method: String,
    #[serde(default = "default_udp_check_dns")]
    pub udp_check_dns: Vec<String>,
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(default = "default_check_tolerance_ms")]
    pub check_tolerance_ms: u64,
    #[serde(default = "default_dial_mode")]
    pub dial_mode: String,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default = "default_sniffing_timeout_ms")]
    pub sniffing_timeout_ms: u64,
    #[serde(default = "default_tls_impl")]
    pub tls_implementation: String,
    #[serde(default = "default_utls_imitate")]
    pub utls_imitate: String,
    #[serde(default)]
    pub tls_fragment: bool,
    #[serde(default)]
    pub tls_fragment_length: String,
    #[serde(default)]
    pub tls_fragment_interval: String,
    #[serde(default)]
    pub mptcp: bool,
    #[serde(default)]
    pub bootstrap_resolver: String,
    #[serde(default = "default_fallback_resolver")]
    pub fallback_resolver: String,
    #[serde(default)]
    pub bandwidth_max_tx: String,
    #[serde(default)]
    pub bandwidth_max_rx: String,
    #[serde(default = "default_udphop_interval_secs")]
    pub udphop_interval_secs: u64,
    /// Timeout for TCP connect (SYN/SYN-ACK) in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Timeout for DNS resolution in the control plane in milliseconds
    /// (used when resolving target domains for non-domain-capable proxies).
    #[serde(default = "default_dns_resolve_timeout_ms")]
    pub dns_resolve_timeout_ms: u64,
    /// Relay idle timeout: if no data flows in either direction for this
    /// many seconds, the relay is terminated. 0 disables the timeout.
    #[serde(default = "default_relay_idle_timeout_secs")]
    pub relay_idle_timeout_secs: u64,
    /// Number of proxy nodes to preconnect on startup. `0` disables the
    /// warm-up entirely; [`PRECONNECT_NODE_COUNT_AUTO`] (dae `'auto'`) picks
    /// `min(nodes, 8)`.
    #[serde(default = "default_preconnect_node_count")]
    pub preconnect_node_count: usize,
    /// Number of selected UDP nodes to warm on startup/reload. Zero strictly
    /// disables this independent warm-up path.
    #[serde(default = "default_udp_warm_node_count")]
    pub udp_warm_node_count: usize,
    /// Process-wide cap on physical proxied connects and protocol handshakes.
    /// Ready-pool hits, logical streams on warm generation transports, and
    /// built-in direct/block dials are exempt.
    #[serde(default = "default_max_concurrent_dials")]
    pub max_concurrent_dials: usize,
}

fn default_tproxy_port() -> u16 {
    12345
}

/// Host CIDRs (`addr/32`, `addr/128`) for every global-scoped address on
/// `iface`. The literal `auto` resolves through the lowest-metric IPv4
/// default route. Missing or unresolved interfaces yield an empty list.
fn interface_host_cidrs(iface: &str) -> Vec<String> {
    let iface = iface.trim();
    let owned;
    let iface = if iface.eq_ignore_ascii_case("auto") {
        owned = default_route_interface().unwrap_or_default();
        if owned.is_empty() {
            return Vec::new();
        }
        owned.as_str()
    } else {
        iface
    };
    // getifaddrs(3) — no `ip` subprocess needed. Link-local addresses
    // (v4 169.254/16, v6 fe80::/10) are excluded, matching the old
    // "not scope link" filter.
    let mut cidrs = Vec::new();
    // SAFETY: getifaddrs allocates a linked list freed by freeifaddrs;
    // all pointers are checked before dereference.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return cidrs;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            if name == iface && !ifa.ifa_addr.is_null() {
                let family = (*ifa.ifa_addr).sa_family as i32;
                if family == libc::AF_INET {
                    // s_addr is network byte order in memory — read it in
                    // native order to get the wire bytes as-is.
                    let a = (*(ifa.ifa_addr as *const libc::sockaddr_in))
                        .sin_addr
                        .s_addr
                        .to_ne_bytes();
                    if !(a[0] == 169 && a[1] == 254) {
                        cidrs.push(format!("{}.{}.{}.{}/32", a[0], a[1], a[2], a[3]));
                    }
                } else if family == libc::AF_INET6 {
                    let a = (*(ifa.ifa_addr as *const libc::sockaddr_in6))
                        .sin6_addr
                        .s6_addr;
                    if !(a[0] == 0xfe && (a[1] & 0xc0) == 0x80) {
                        cidrs.push(format!("{}/128", std::net::Ipv6Addr::from(a)));
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    cidrs
}

/// Interface owning the lowest-metric IPv4 default route.
pub fn default_route_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    default_route_interface_from(&text)
}

/// Parse `/proc/net/route` and select a real destination/mask-zero route.
pub fn default_route_interface_from(text: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(interface) = fields.next() else {
            continue;
        };
        let Some(destination) = fields.next() else {
            continue;
        };
        let Some(metric) = fields.nth(4) else {
            continue;
        };
        let Some(mask) = fields.next() else {
            continue;
        };
        if destination != "00000000" || mask != "00000000" {
            continue;
        }
        let metric = metric.parse::<u32>().unwrap_or(u32::MAX);
        if best.as_ref().is_none_or(|(current, _)| metric < *current) {
            best = Some((metric, interface.to_string()));
        }
    }
    best.map(|(_, interface)| interface)
}

fn default_tproxy_mark() -> u32 {
    DEFAULT_TPROXY_MARK
}

/// The only valid `global.tproxy_mark`: the eBPF datapath has the mark
/// compiled in, so userspace cannot honor any other value. honk-core pins
/// this against `honk_ebpf_common::TPROXY_MARK` with a unit test.
pub const DEFAULT_TPROXY_MARK: u32 = 0x0800_0000;
fn default_log_level() -> String {
    "info".into()
}
fn default_tcp_check_urls() -> Vec<String> {
    vec!["https://www.gstatic.com/generate_204".into()]
}
fn default_tcp_check_http_method() -> String {
    "HEAD".into()
}
fn default_udp_check_dns() -> Vec<String> {
    vec![
        "dns.google:53".into(),
        "8.8.8.8".into(),
        "2001:4860:4860::8888".into(),
    ]
}
fn default_check_interval_secs() -> u64 {
    30
}
fn default_check_tolerance_ms() -> u64 {
    50
}
fn default_dial_mode() -> String {
    "domain".into()
}
fn default_sniffing_timeout_ms() -> u64 {
    30
}
fn default_tls_impl() -> String {
    "tls".into()
}
fn default_utls_imitate() -> String {
    "chrome_auto".into()
}
fn default_fallback_resolver() -> String {
    "8.8.8.8:53".into()
}
fn default_udphop_interval_secs() -> u64 {
    30
}
fn default_connect_timeout_ms() -> u64 {
    3000
}
fn default_dns_resolve_timeout_ms() -> u64 {
    2000
}
fn default_relay_idle_timeout_secs() -> u64 {
    300
}
fn default_preconnect_node_count() -> usize {
    PRECONNECT_NODE_COUNT_AUTO
}
fn default_udp_warm_node_count() -> usize {
    0
}
fn default_data_dir() -> String {
    crate::paths::DEFAULT_DATA_DIR.to_string()
}
fn default_store_subscribe() -> bool {
    true
}
fn default_max_concurrent_dials() -> usize {
    64
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            tproxy_port: default_tproxy_port(),
            tproxy_mark: default_tproxy_mark(),
            tproxy_port_protect: true,
            pprof_port: 0,
            so_mark_from_dae: 0,
            log_level: default_log_level(),
            log_file: String::new(),
            disable_waiting_network: false,
            lan_interface: vec![],
            wan_interface: vec![],
            auto_config_kernel_parameter: false,
            nfqueue_enable: true,
            data_dir: default_data_dir(),
            store_subscribe: default_store_subscribe(),
            tcp_check_url: default_tcp_check_urls(),
            tcp_check_http_method: default_tcp_check_http_method(),
            udp_check_dns: default_udp_check_dns(),
            check_interval_secs: default_check_interval_secs(),
            check_tolerance_ms: default_check_tolerance_ms(),
            dial_mode: default_dial_mode(),
            allow_insecure: false,
            sniffing_timeout_ms: default_sniffing_timeout_ms(),
            tls_implementation: default_tls_impl(),
            utls_imitate: default_utls_imitate(),
            tls_fragment: false,
            tls_fragment_length: String::new(),
            tls_fragment_interval: String::new(),
            mptcp: false,
            bootstrap_resolver: String::new(),
            fallback_resolver: default_fallback_resolver(),
            bandwidth_max_tx: String::new(),
            bandwidth_max_rx: String::new(),
            udphop_interval_secs: default_udphop_interval_secs(),
            connect_timeout_ms: default_connect_timeout_ms(),
            dns_resolve_timeout_ms: default_dns_resolve_timeout_ms(),
            relay_idle_timeout_secs: default_relay_idle_timeout_secs(),
            preconnect_node_count: default_preconnect_node_count(),
            udp_warm_node_count: default_udp_warm_node_count(),
            max_concurrent_dials: default_max_concurrent_dials(),
        }
    }
}

impl Config {
    /// The built-in `direct` node name (usable as a group member without
    /// being declared in the config).
    pub const BUILTIN_DIRECT_NODE: &'static str = "direct";
    /// The built-in `block` node name.
    pub const BUILTIN_BLOCK_NODE: &'static str = "block";

    /// Inject the built-in `direct`/`block` nodes unless the config already
    /// defines nodes with those names. Idempotent.
    ///
    /// This makes both built-ins first-class group members (Selector/urltest
    /// candidates, delay-test targets) without declaring them in the config
    /// file; their address fields are unused.
    pub fn ensure_builtin_nodes(&mut self) {
        for builtin in [Self::builtin_direct_node(), Self::builtin_block_node()] {
            if !self.nodes.iter().any(|n| n.name == builtin.name) {
                self.nodes.push(builtin);
            }
        }
    }

    /// The built-in node registered under `name`, falling back to a fresh
    /// built-in definition when [`Self::ensure_builtin_nodes`] has not run.
    /// `None` for any non-built-in name.
    pub fn builtin_node(&self, name: &str) -> Option<crate::node::Node> {
        let fresh = match name {
            Self::BUILTIN_DIRECT_NODE => Self::builtin_direct_node(),
            Self::BUILTIN_BLOCK_NODE => Self::builtin_block_node(),
            _ => return None,
        };
        Some(
            self.nodes
                .iter()
                .find(|n| n.name == name)
                .cloned()
                .unwrap_or(fresh),
        )
    }

    /// A fresh built-in `direct` node definition.
    pub fn builtin_direct_node() -> crate::node::Node {
        crate::node::Node {
            id: DIRECT_NODE_ID,
            name: Self::BUILTIN_DIRECT_NODE.to_string(),
            outbound: crate::node::OutboundConfig::Direct,
            ..Default::default()
        }
    }

    /// A fresh built-in `block` node definition.
    pub fn builtin_block_node() -> crate::node::Node {
        crate::node::Node {
            id: BLOCK_NODE_ID,
            name: Self::BUILTIN_BLOCK_NODE.to_string(),
            outbound: crate::node::OutboundConfig::Block,
            ..Default::default()
        }
    }

    /// Current host CIDRs on configured LAN/WAN interfaces. Missing
    /// interfaces and an unresolved `auto` entry are omitted.
    pub fn local_direct_cidrs(&self) -> Vec<String> {
        let mut cidrs = Vec::new();
        for iface in &self.global.lan_interface {
            cidrs.extend(interface_host_cidrs(iface));
        }
        for iface in &self.global.wan_interface {
            cidrs.extend(interface_host_cidrs(iface));
        }
        cidrs.sort();
        cidrs.dedup();
        cidrs
    }

    /// Inject terminal must-direct routing rules for every address assigned to
    /// configured lan/wan interfaces, so traffic to the gateway itself
    /// (admin UI, SSH, clash API) bypasses the proxy even when every node is
    /// dead. Generated rules use priority 0 and are appended after user rules:
    /// they outrank user rules with a higher priority, while stable equal-
    /// priority ordering lets an existing user priority-0 rule win first.
    ///
    /// Best-effort and idempotent: interfaces that cannot be read
    /// (missing, `auto` without a default route) are skipped. Returns whether
    /// the generated address set changed.
    pub fn ensure_local_direct_rules(&mut self) -> bool {
        const MARK: &str = "__local_direct_";
        let mut previous: Vec<String> = self
            .routing
            .rules
            .iter()
            .filter_map(|rule| rule.name.strip_prefix(MARK).map(str::to_owned))
            .collect();
        previous.sort();
        previous.dedup();
        self.routing
            .rules
            .retain(|rule| !rule.name.starts_with(MARK));

        let cidrs = self.local_direct_cidrs();
        let changed = previous != cidrs;
        for cidr in cidrs {
            self.routing.rules.push(crate::routing::RoutingRule {
                name: format!("{MARK}{cidr}"),
                condition: crate::routing::RoutingCondition {
                    ip: vec![cidr],
                    ..Default::default()
                },
                outbound: crate::routing::RoutingOutbound::Simple("direct".to_string()),
                priority: 0,
                must: true,
                mark: 0,
            });
        }
        changed
    }

    /// Apply the removed experimental NFQUEUE setting without retaining it in
    /// the active configuration schema.
    pub(crate) fn apply_legacy_nfqueue(&mut self, canonical_present: bool) {
        let Some(legacy) = self.experimental.legacy_udp_nfqueue.take() else {
            return;
        };
        if !canonical_present {
            self.global.nfqueue_enable = legacy.enabled;
        }
    }

    pub fn from_file(path: &str) -> Result<Self, crate::ConfigError> {
        let mut diagnostics = Vec::new();
        let result = Self::from_file_with_detailed_diagnostics(path, &mut diagnostics);
        report_detailed_diagnostics(&diagnostics);
        result.map_err(DetailedConfigError::into_legacy)
    }

    /// Compatibility projection of the detailed data API; never logs.
    pub fn from_file_with_diagnostics(
        path: &str,
        diagnostics: &mut Vec<ConfigDiagnostic>,
    ) -> Result<Self, crate::ConfigError> {
        let mut detailed = Vec::new();
        let result = Self::from_file_with_detailed_diagnostics(path, &mut detailed);
        diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
        result.map_err(DetailedConfigError::into_legacy)
    }

    /// Load with failure-preserving diagnostics. Each format owns a separate source table.
    pub fn from_file_with_detailed_diagnostics(
        path: &str,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, DetailedConfigError> {
        let result = Self::load_file_attempt(path, diagnostics);
        finish_attempt(result, diagnostics)
    }

    fn load_file_attempt(
        path: &str,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, DetailedConfigError> {
        let source = DiagnosticSources::new(Some(path.into())).root();
        let content = std::fs::read_to_string(path)
            .map_err(|error| DetailedConfigError::from_legacy(error.into(), source.clone()))?;
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase);
        let start = diagnostics.len();
        let formats: &[ConfigFormat] = match ext.as_deref() {
            Some("json") => &[ConfigFormat::Json, ConfigFormat::Toml, ConfigFormat::Yaml],
            Some("yaml" | "yml") => &[ConfigFormat::Yaml, ConfigFormat::Toml, ConfigFormat::Json],
            Some("toml") => &[ConfigFormat::Toml, ConfigFormat::Yaml, ConfigFormat::Json],
            _ => {
                let mut semantic = false;
                let result =
                    crate::parser::parse_dae_config_file_attempt(path, diagnostics, &mut semantic);
                match result {
                    Ok(mut config) => {
                        config.derive_node_ids();
                        return Ok(config);
                    }
                    Err(error) => {
                        let stop = matches!(
                            error.category,
                            ErrorCategory::Include | ErrorCategory::UnsupportedPolicy
                        );
                        let mut error = error;
                        // File-mode legacy callers historically received the last Parse error.
                        if !stop && semantic {
                            error.category = ErrorCategory::Parse;
                        }
                        if stop || semantic {
                            return Err(error);
                        }
                        let mut diagnostic = *error.diagnostic;
                        diagnostic.terminal = false;
                        diagnostics.push(diagnostic);
                    }
                }
                &[ConfigFormat::Toml, ConfigFormat::Yaml, ConfigFormat::Json]
            }
        };
        for (index, format) in formats.iter().enumerate() {
            let attempt_start = diagnostics.len();
            let source = DiagnosticSources::new(Some(path.into())).root();
            match parse_structured(&content, *format, diagnostics, source) {
                Ok(mut config) => {
                    diagnostics.drain(start..attempt_start);
                    config.derive_node_ids();
                    return Ok(config);
                }
                Err(error) => {
                    if index + 1 == formats.len() {
                        if error.diagnostic.entry_index.is_none()
                            && let Some(cause_index) =
                                diagnostics[start..].iter().position(|diagnostic| {
                                    diagnostic.severity == crate::diagnostic::Severity::Error
                                        && diagnostic.entry_index.is_some()
                                })
                        {
                            let mut cause = diagnostics.remove(start + cause_index);
                            cause.terminal = true;
                            let mut last_attempt = *error.diagnostic;
                            last_attempt.terminal = false;
                            diagnostics.push(last_attempt);
                            return Err(DetailedConfigError {
                                category: error.category,
                                diagnostic: Box::new(cause),
                            });
                        }
                        return Err(error);
                    }
                    let mut diagnostic = *error.diagnostic;
                    diagnostic.terminal = false;
                    diagnostics.push(diagnostic);
                }
            }
        }
        unreachable!("format list is nonempty")
    }

    pub fn to_file(&self, path: &str) -> Result<(), crate::ConfigError> {
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);

        let content = match ext.as_deref() {
            Some("dae") => {
                return Err(crate::ConfigError::Serialization(
                    "refusing to rewrite .dae configuration: source formatting, comments, and includes cannot be preserved; edit the dae source directly or use .toml/.yaml/.json"
                        .into(),
                ));
            }
            Some("json") => self.to_json_string()?,
            Some("yaml") | Some("yml") => serde_yaml::to_string(self)
                .map_err(|e| crate::ConfigError::Serialization(e.to_string()))?,
            _ => toml::to_string_pretty(self)
                .map_err(|e| crate::ConfigError::Serialization(e.to_string()))?,
        };
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Serialize the configuration to a pretty-printed JSON string.
    pub fn to_json_string(&self) -> Result<String, crate::ConfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::ConfigError::Serialization(e.to_string()))
    }

    /// Parse a configuration from a JSON string.
    pub fn from_json_str(s: &str) -> Result<Self, crate::ConfigError> {
        let mut diagnostics = Vec::new();
        let result = Self::from_json_str_with_detailed_diagnostics(s, &mut diagnostics);
        report_detailed_diagnostics(&diagnostics);
        result.map_err(DetailedConfigError::into_legacy)
    }

    pub fn from_json_str_with_detailed_diagnostics(
        s: &str,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, DetailedConfigError> {
        let result = parse_structured(
            s,
            ConfigFormat::Json,
            diagnostics,
            DiagnosticSources::new(None).root(),
        )
        .map(|mut config| {
            config.derive_node_ids();
            config
        });
        finish_attempt(result, diagnostics)
    }

    /// Re-derive every node's content-based ID ([`Node::derive_id`]) after
    /// load. Stored/serde-default IDs are discarded so identity always
    /// reflects the current content; the built-in direct/block nodes keep
    /// their fixed IDs.
    fn derive_node_ids(&mut self) {
        for node in &mut self.nodes {
            if node.id == DIRECT_NODE_ID || node.id == BLOCK_NODE_ID {
                continue;
            }
            node.id = node.derive_id();
        }
    }

    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        if self.global.dial_mode.parse::<DialMode>().is_err() {
            return Err(crate::ConfigError::Validation(format!(
                "global.dial_mode must be one of: ip, domain, domain+, domain++ (got '{}')",
                self.global.dial_mode
            )));
        }

        let data_dir = std::path::Path::new(&self.global.data_dir);
        if self.global.data_dir.is_empty() || !data_dir.is_absolute() {
            return Err(crate::ConfigError::Validation(
                "global.data_dir must be a non-empty absolute path".into(),
            ));
        }

        self.dns
            .bind_endpoint()
            .map_err(|error| crate::ConfigError::Validation(error.to_string()))?;
        self.dns
            .client_subnet_mode()
            .map_err(|error| crate::ConfigError::Validation(error.to_string()))?;

        self.dns.validate_upstream_references()?;

        // A duration that fails to parse becomes zero, and a zero period makes
        // tokio::time::interval panic, taking the health-check loop down at startup.
        if self.global.check_interval_secs == 0 {
            return Err(crate::ConfigError::Validation(
                "global.check_interval must be a positive duration, such as 30s".into(),
            ));
        }

        // The eBPF datapath has the mark compiled in; userspace cannot inject
        // a different value, so a custom mark would silently break the proxy.
        if self.global.tproxy_mark != default_tproxy_mark() {
            return Err(crate::ConfigError::Validation(format!(
                "global.tproxy_mark must be {:#x} (compiled into the eBPF datapath)",
                default_tproxy_mark()
            )));
        }
        let reserved = crate::routing::DATAPATH_RESERVED_MARK_MASK;
        if self.global.so_mark_from_dae & reserved != 0 {
            return Err(crate::ConfigError::Validation(format!(
                "global.so_mark_from_dae ({:#x}) overlaps datapath-reserved skb mark bits {reserved:#x}",
                self.global.so_mark_from_dae
            )));
        }
        for (index, rule) in self.routing.rules.iter().enumerate() {
            if rule.mark & reserved == 0 {
                continue;
            }
            let rule_name = if rule.name.is_empty() {
                format!("routing.rules[{index}].mark")
            } else {
                format!("routing rule '{}'.mark", rule.name)
            };
            return Err(crate::ConfigError::Validation(format!(
                "{rule_name} ({:#x}) overlaps datapath-reserved skb mark bits {reserved:#x}",
                rule.mark
            )));
        }
        // Content-derived IDs collide when two nodes share protocol, server,
        // and credentials — they are the same endpoint and cannot coexist
        // in the runtime registry.
        let mut ids: std::collections::HashMap<uuid::Uuid, &str> = std::collections::HashMap::new();
        for node in &self.nodes {
            if node.id.is_nil() {
                continue;
            }
            if let Some(prev) = ids.insert(node.id, &node.name)
                && prev != node.name
            {
                return Err(crate::ConfigError::Validation(format!(
                    "Nodes '{}' and '{}' derive the same ID (identical protocol, server and credentials)",
                    prev, node.name
                )));
            }
        }
        for node in &self.nodes {
            // The injected built-ins carry no dialable address by design.
            if node.id == DIRECT_NODE_ID || node.id == BLOCK_NODE_ID {
                continue;
            }
            if node.name.is_empty() {
                return Err(crate::ConfigError::Validation(
                    "Node name cannot be empty".into(),
                ));
            }
            if node.address.is_empty() && node.host.is_empty() {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{}' has no address or host",
                    node.name
                )));
            }
            // Reject unknown transports at load time instead of silently
            // degrading to raw TCP at dial time.
            if let Some(transport) = node.transport()
                && !matches!(transport.transport.as_str(), "" | "tcp" | "ws" | "grpc")
            {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{}' has unsupported transport '{}' (expected tcp/ws/grpc)",
                    node.name, transport.transport
                )));
            }
            if let Some(vless) = node.vless()
                && let Some(flow) = vless.flow.as_deref()
            {
                if vless.tls.reality_public_key.is_none() && !vless.tls.enabled {
                    return Err(crate::ConfigError::Validation(format!(
                        "Node '{}' sets flow '{}' without TLS or REALITY",
                        node.name, flow
                    )));
                }
                if flow != "xtls-rprx-vision" {
                    return Err(crate::ConfigError::Validation(format!(
                        "Node '{}' has unsupported flow '{}' (expected xtls-rprx-vision)",
                        node.name, flow
                    )));
                }
            }
            node.validate_protocol()?;
            // direct/block are the injected built-ins; a user node may
            // neither take their names nor their protocols.
            if matches!(
                node.name.as_str(),
                Self::BUILTIN_DIRECT_NODE | Self::BUILTIN_BLOCK_NODE
            ) || matches!(
                node.protocol(),
                crate::types::NodeProtocol::Direct | crate::types::NodeProtocol::Block
            ) {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{}' uses a name or protocol reserved for the built-in direct/block nodes",
                    node.name
                )));
            }
        }
        // User groups occupy ordinals 2..=251; 252 and above are reserved
        // protocol values (must/control-plane/logical operators).
        const MAX_USER_GROUPS: usize = 0xFC - 2;
        if self.groups.len() > MAX_USER_GROUPS {
            return Err(crate::ConfigError::Validation(format!(
                "too many outbound groups: {} (maximum is {MAX_USER_GROUPS})",
                self.groups.len()
            )));
        }
        for group in &self.groups {
            if group.name.is_empty() {
                return Err(crate::ConfigError::Validation(
                    "Group name cannot be empty".into(),
                ));
            }
            if self.nodes.iter().any(|node| {
                node.id != DIRECT_NODE_ID && node.id != BLOCK_NODE_ID && node.name == group.name
            }) {
                return Err(crate::ConfigError::Validation(format!(
                    "name '{}' is defined as both a node and a group; rename one of them",
                    group.name
                )));
            }
        }
        // Routing outbounds resolve only against group names and the built-in
        // direct/block. A bare node name has no eBPF outbound id, so accepting
        // it would silently misroute; subscription nodes arrive at runtime and
        // are deliberately out of scope here. group.final and DNS upstream
        // detours legitimately accept node names and stay unchecked.
        let is_config_node = |name: &str| {
            self.nodes.iter().any(|node| {
                node.id != DIRECT_NODE_ID && node.id != BLOCK_NODE_ID && node.name == name
            })
        };
        let check_outbound = |outbound: &str, fallback: bool| -> Result<(), crate::ConfigError> {
            let kind = if fallback { "fallback" } else { "outbound" };
            if matches!(
                outbound,
                Self::BUILTIN_DIRECT_NODE | Self::BUILTIN_BLOCK_NODE
            ) || self.groups.iter().any(|group| group.name == outbound)
            {
                return Ok(());
            }
            if is_config_node(outbound) {
                return Err(crate::ConfigError::Validation(format!(
                    "{kind} '{outbound}' is a node, not a group; wrap it in a group (e.g. filter: name('{outbound}')) or reference a group"
                )));
            }
            Err(crate::ConfigError::Validation(format!(
                "unknown {kind} '{outbound}' (expected a group name, 'direct', or 'block')"
            )))
        };
        for rule in &self.routing.rules {
            check_outbound(rule.outbound.as_str(), false)?;
        }
        check_outbound(&self.routing.default_outbound, true)?;
        for subscription in &self.subscriptions {
            if subscription.name.is_empty() {
                return Err(crate::ConfigError::Validation(
                    "subscription name must not be empty".into(),
                ));
            }
            if subscription.url.is_empty() {
                return Err(crate::ConfigError::Validation(format!(
                    "subscription '{}' has an empty url",
                    subscription.name
                )));
            }
            if !subscription.url.starts_with("http://") && !subscription.url.starts_with("https://")
            {
                return Err(crate::ConfigError::Validation(format!(
                    "subscription '{}' url must use http:// or https://",
                    subscription.name
                )));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum ConfigFormat {
    Json,
    Yaml,
    Toml,
}

#[derive(Default)]
struct DecodeLocation {
    span: Option<Range<usize>>,
    line: Option<usize>,
    byte_column: Option<usize>,
    reason: Option<&'static str>,
}

fn parse_structured(
    content: &str,
    format: ConfigFormat,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    source: SourceRef,
) -> Result<Config, DetailedConfigError> {
    let mut track = Track::new();
    let seed = RawConfigSeed {
        diagnostics,
        source: source.clone(),
    };
    let result = match format {
        ConfigFormat::Json => {
            let mut decoder = serde_json::Deserializer::from_str(content);
            seed.deserialize(PathDeserializer::new(&mut decoder, &mut track))
                .and_then(|config| decoder.end().map(|_| config))
                .map_err(|error| DecodeLocation {
                    line: (error.line() != 0).then_some(error.line()),
                    byte_column: (error.column() != 0).then_some(error.column()),
                    span: None,
                    reason: Some(safe_json_reason(&error)),
                })
        }
        ConfigFormat::Yaml => seed
            .deserialize(PathDeserializer::new(
                serde_yaml::Deserializer::from_str(content),
                &mut track,
            ))
            .map_err(|error| {
                let location = error.location();
                DecodeLocation {
                    line: location.as_ref().map(|location| location.line()),
                    byte_column: location.as_ref().and_then(|location| {
                        let line = content.lines().nth(location.line().checked_sub(1)?)?;
                        let column = location.column().checked_sub(1)?;
                        Some(
                            line.char_indices()
                                .nth(column)
                                .map_or(line.len(), |(i, _)| i)
                                + 1,
                        )
                    }),
                    span: None,
                    reason: None,
                }
            }),
        ConfigFormat::Toml => toml::de::Deserializer::parse(content)
            .and_then(|decoder| seed.deserialize(PathDeserializer::new(decoder, &mut track)))
            .map_err(|error| toml_location(content, &error)),
    };
    let mut config =
        result.map_err(|location| structured_decode_error(source, track.path(), location))?;
    let canonical_present = match format {
        ConfigFormat::Json => json_has_global_nfqueue_enable(content),
        ConfigFormat::Yaml => yaml_has_global_nfqueue_enable(content),
        ConfigFormat::Toml => toml_has_global_nfqueue_enable(content),
    };
    config.apply_legacy_nfqueue(canonical_present);
    Ok(config)
}

fn safe_json_reason(error: &serde_json::Error) -> &'static str {
    // Decoder prose is transient. Only these schema-defined reasons may escape.
    let text = error.to_string();
    let reason = text
        .rsplit_once(" at line ")
        .map_or(text.as_str(), |(reason, _)| reason);
    if reason == "expected value" {
        "expected a JSON value"
    } else if reason == "expected ident" {
        "invalid JSON literal"
    } else if reason.starts_with("unknown field `") && reason.ends_with("expected `enabled`") {
        "unknown field; expected enabled"
    } else if reason.starts_with("invalid type:") {
        if reason.ends_with("expected struct Group") {
            "expected a group object"
        } else if reason.ends_with("expected a sequence") {
            "expected a sequence"
        } else {
            "incorrect value type for configuration field"
        }
    } else {
        match error.classify() {
            serde_json::error::Category::Io => "configuration IO failed",
            serde_json::error::Category::Syntax => "invalid JSON syntax",
            serde_json::error::Category::Eof => "incomplete JSON input",
            serde_json::error::Category::Data => "invalid configuration fields",
        }
    }
}

fn toml_location(content: &str, error: &toml::de::Error) -> DecodeLocation {
    let Some(span) = error.span() else {
        return DecodeLocation::default();
    };
    let start = span.start.min(content.len());
    let prefix = &content.as_bytes()[..start];
    let line = prefix.iter().filter(|&&byte| byte == b'\n').count() + 1;
    let byte_column = prefix
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(start + 1, |newline| start - newline);
    DecodeLocation {
        span: Some(span),
        line: Some(line),
        byte_column: Some(byte_column),
        reason: None,
    }
}

fn structured_decode_error(
    source: SourceRef,
    path: serde_path_to_error::Path,
    location: DecodeLocation,
) -> DetailedConfigError {
    let (setting, entry_index) = setting_from_decode_path(&path);
    let mut error = DetailedConfigError::new(
        ErrorCategory::Parse,
        "invalid-structured-config",
        source,
        setting,
        location.reason.unwrap_or("invalid configuration fields"),
    );
    error.diagnostic.entry_index = entry_index;
    error.diagnostic.span = location.span;
    error.diagnostic.line = location.line;
    error.diagnostic.byte_column = location.byte_column;
    error
}

fn setting_from_decode_path(path: &serde_path_to_error::Path) -> (SettingPath, Option<usize>) {
    let mut segments = path.iter();
    let root = match segments.next() {
        Some(Segment::Map { key }) => seed::CONFIG_FIELDS
            .iter()
            .copied()
            .find(|&field| field == key),
        Some(Segment::Seq { index }) => seed::CONFIG_FIELDS.get(*index).copied(),
        _ => None,
    };
    let Some(root) = root else {
        return (SettingPath::new("config"), None);
    };
    let mut setting = SettingPath::new(root);
    let mut entry_index = None;
    let mut field_seen = false;
    for segment in segments {
        match segment {
            Segment::Seq { index } if matches!(root, "nodes" | "groups" | "subscriptions") => {
                let index = index + 1;
                setting = setting.index(index);
                entry_index.get_or_insert(index);
            }
            Segment::Map { key } if !field_seen => {
                let field = match root {
                    "nodes" if entry_index.is_some() => node_schema_field(key),
                    "groups" if entry_index.is_some() => [
                        "id",
                        "name",
                        "policy",
                        "nodes",
                        "filters",
                        "groups",
                        "default",
                        "final_outbound",
                        "check_url",
                        "check_interval",
                        "tolerance",
                        "idle_timeout",
                        "interrupt_connections",
                        "created_at",
                    ]
                    .into_iter()
                    .find(|field| field == key),
                    "subscriptions" if entry_index.is_some() => [
                        "id",
                        "name",
                        "url",
                        "sub_type",
                        "update_interval",
                        "user_agent",
                        "headers",
                        "enabled",
                        "last_updated",
                        "node_count",
                        "created_at",
                    ]
                    .into_iter()
                    .find(|field| field == key),
                    _ => None,
                };
                let Some(field) = field else {
                    break;
                };
                setting = setting.field(field);
                field_seen = true;
            }
            _ => break,
        }
    }
    (setting, entry_index)
}

fn node_schema_field(field: &str) -> Option<&'static str> {
    Some(match field {
        "id" => "id",
        "name" => "name",
        "address" => "address",
        "host" => "host",
        "port" => "port",
        "protocol" => "protocol",
        "username" => "username",
        "password" => "password",
        "encryption" => "encryption",
        "vless_mode" => "vless_mode",
        "plugin" => "plugin",
        "plugin_opts" => "plugin_opts",
        "transport" => "transport",
        "tls" => "tls",
        "sni" => "sni",
        "tls_alpn" => "tls_alpn",
        "skip_cert_verify" => "skip_cert_verify",
        "ech_enabled" => "ech_enabled",
        "ech_config" => "ech_config",
        "ech_config_path" => "ech_config_path",
        "reality_public_key" => "reality_public_key",
        "reality_short_id" => "reality_short_id",
        "reality_spider_x" => "reality_spider_x",
        "flow" => "flow",
        "network" => "network",
        "ws_path" => "ws_path",
        "ws_host" => "ws_host",
        "grpc_service" => "grpc_service",
        "hy2_auth" => "hy2_auth",
        "hy2_obfs" => "hy2_obfs",
        "hy2_up_mbps" => "hy2_up_mbps",
        "hy2_down_mbps" => "hy2_down_mbps",
        "hy2_port_hopping" => "hy2_port_hopping",
        "hy2_hop_interval" => "hy2_hop_interval",
        "tls_pin_sha256" => "tls_pin_sha256",
        "hy2_init_stream_recv_window" => "hy2_init_stream_recv_window",
        "hy2_init_conn_recv_window" => "hy2_init_conn_recv_window",
        "hy2_disable_mtu_discovery" => "hy2_disable_mtu_discovery",
        "quic_mtu" => "quic_mtu",
        "tuic_uuid" => "tuic_uuid",
        "tuic_password" => "tuic_password",
        "tuic_congestion" => "tuic_congestion",
        "tuic_alpn" => "tuic_alpn",
        "tuic_init_stream_recv_window" => "tuic_init_stream_recv_window",
        "tuic_init_conn_recv_window" => "tuic_init_conn_recv_window",
        "juicity_uuid" => "juicity_uuid",
        "juicity_password" => "juicity_password",
        "anytls_password" => "anytls_password",
        "anytls_min_idle_session" => "anytls_min_idle_session",
        "anytls_idle_session_check_interval" => "anytls_idle_session_check_interval",
        "anytls_idle_session_timeout" => "anytls_idle_session_timeout",
        "mark" => "mark",
        "tags" => "tags",
        "subscription_id" => "subscription_id",
        "group_id" => "group_id",
        "created_at" => "created_at",
        "updated_at" => "updated_at",
        _ => return None,
    })
}

fn json_has_global_nfqueue_enable(content: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|root| root.get("global").cloned())
        .and_then(|global| global.as_object().cloned())
        .is_some_and(|global| global.contains_key("nfqueue_enable"))
}

fn toml_has_global_nfqueue_enable(content: &str) -> bool {
    toml::from_str::<toml::Value>(content)
        .ok()
        .and_then(|root| root.get("global").cloned())
        .and_then(|global| global.as_table().cloned())
        .is_some_and(|global| global.contains_key("nfqueue_enable"))
}

fn yaml_has_global_nfqueue_enable(content: &str) -> bool {
    serde_yaml::from_str::<serde_yaml::Value>(content)
        .ok()
        .and_then(|root| root.get("global").cloned())
        .and_then(|global| global.as_mapping().cloned())
        .is_some_and(|global| {
            global.contains_key(serde_yaml::Value::String("nfqueue_enable".into()))
        })
}

#[cfg(test)]
mod builtin_nodes_tests {
    use super::*;

    #[test]
    fn test_validate_accepts_supported_dns_bind() {
        let mut config = Config::default();
        config.dns.bind = "tcp+udp://localhost:0".into();
        config.validate().unwrap();
    }

    #[test]
    fn test_validate_rejects_invalid_subscriptions() {
        let valid = crate::subscription::Subscription {
            name: "sub".into(),
            url: "https://example.test/feed".into(),
            ..Default::default()
        };
        let mut config = Config::default();
        config.subscriptions.push(valid.clone());
        config.validate().unwrap();

        for (name, url) in [
            ("", "https://example.test/feed"),
            ("sub", ""),
            ("sub", "ftp://example.test/feed"),
        ] {
            let mut config = Config::default();
            let mut sub = valid.clone();
            sub.name = name.into();
            sub.url = url.into();
            config.subscriptions.push(sub);
            assert!(
                config.validate().is_err(),
                "name={name:?} url={url:?} must fail validation"
            );
        }
    }

    #[test]
    fn test_validate_rejects_zero_check_interval() {
        let mut config = Config::default();
        config.global.check_interval_secs = 0;
        let error = config.validate().unwrap_err();
        assert!(
            error.to_string().contains("global.check_interval"),
            "validation error must identify global.check_interval: {error}"
        );
    }

    #[test]
    fn test_validate_rejects_unknown_dial_mode() {
        let mut config = Config::default();
        config.global.dial_mode = "domain???".into();
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("global.dial_mode"));
    }

    #[test]
    fn test_validate_rejects_invalid_structured_dns_bind_clearly() {
        let config = Config::from_json_str(r#"{"dns":{"bind":"udp://localhost"}}"#).unwrap();
        let error = config.validate().unwrap_err();
        assert!(matches!(error, crate::ConfigError::Validation(_)));
        assert!(
            error.to_string().contains("dns.bind"),
            "validation error must identify dns.bind: {error}"
        );
    }

    #[test]
    fn test_from_json_accepts_legacy_null_dns_routing_fields() {
        let config =
            Config::from_json_str(r#"{"dns":{"routing":{"request":null,"response":null}}}"#)
                .unwrap();

        assert!(config.dns.routing.request.rules.is_empty());
        assert!(config.dns.routing.response.rules.is_empty());
    }

    #[test]
    fn test_from_file_preserves_renamed_honk_policy_error() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "group {\n proxy {\n policy: honk\n }\n}").unwrap();
        let error = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(error, crate::ConfigError::UnsupportedPolicy(_)));
    }

    #[test]
    fn test_validate_rejects_invalid_structured_dns_client_subnet() {
        let config =
            Config::from_json_str(r#"{"dns":{"client_subnet":"auto(dns.google)"}}"#).unwrap();
        let error = config.validate().unwrap_err();
        assert!(matches!(error, crate::ConfigError::Validation(_)));
        assert!(error.to_string().contains("dns.client_subnet"));
    }

    #[test]
    fn test_validate_requires_absolute_data_dir() {
        let mut config = Config::default();
        assert_eq!(config.global.data_dir, crate::paths::DEFAULT_DATA_DIR);
        config.validate().unwrap();

        for invalid in ["", "relative/data"] {
            config.global.data_dir = invalid.into();
            let error = config.validate().unwrap_err();
            assert!(error.to_string().contains("global.data_dir"));
        }
    }

    #[test]
    fn test_validate_rejects_datapath_reserved_routing_marks() {
        let mut config = Config::default();
        config.routing.rules.push(crate::routing::RoutingRule {
            name: "reserved-mark".into(),
            condition: crate::routing::RoutingCondition::default(),
            outbound: crate::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });

        for reserved_bit in [0x4000_0000, 0x8000_0000] {
            config.routing.rules[0].mark = reserved_bit;
            let error = config
                .validate()
                .expect_err("reserved routing mark must fail");
            assert!(error.to_string().contains("reserved skb mark"), "{error}");
        }

        config.routing.rules[0].mark = 0x3fff_ffff;
        config.global.so_mark_from_dae = 0x8000_0000;
        assert!(config.validate().is_err());
        config.global.so_mark_from_dae = 0;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_reserved_group_ordinal_overflow() {
        let mut config = Config::default();
        for index in 0..=250 {
            config.groups.push(crate::group::Group {
                name: format!("group-{index}"),
                ..Default::default()
            });
        }
        let error = config
            .validate()
            .expect_err("reserved user-group ordinal must fail validation");
        assert!(error.to_string().contains("too many outbound groups"));

        config.groups.pop();
        assert!(
            config.validate().is_ok(),
            "the last valid group ordinal must pass"
        );
    }

    #[test]
    fn test_validate_rejects_unknown_transport() {
        let mut config = Config::default();
        config.nodes.push(crate::node::Node {
            name: "bad".into(),
            address: "1.2.3.4:443".into(),
            outbound: crate::node::OutboundConfig::Trojan(crate::node::TrojanConfig {
                transport: crate::node::StreamTransportOptions {
                    transport: "kcp".into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        });
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("unsupported transport"),
            "unknown transport must be rejected at load: {err}"
        );
        for ok in ["", "tcp", "ws", "grpc"] {
            config.nodes[0].transport_mut().unwrap().transport = ok.into();
            assert!(config.validate().is_ok(), "transport '{ok}' must pass");
        }
    }

    #[test]
    fn test_validate_rejects_vless_mode_conflicts() {
        let base = crate::node::Node::from_share_link(
            "vless://uuid@example.com:443?vless_mode=h2mux#vless",
        )
        .unwrap();

        let mut config = Config::default();
        config.nodes.push(base.clone());
        assert!(config.validate().is_ok());

        for mode in [
            crate::node::WireMode::UotV2,
            crate::node::WireMode::H2mux,
            crate::node::WireMode::H2muxPadded,
            crate::node::WireMode::MuxCool,
        ] {
            config.nodes[0] = base.clone();
            let vless = config.nodes[0].vless_mut().unwrap();
            vless.mode = mode;
            vless.flow = Some("xtls-rprx-vision".into());
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("with flow")
            );
        }
        config.nodes[0] = base.clone();
        let vless = config.nodes[0].vless_mut().unwrap();
        vless.mode = crate::node::WireMode::Xudp;
        vless.flow = Some("xtls-rprx-vision".into());
        assert!(config.validate().is_ok());

        config.nodes[0] = base;
        config.nodes[0].vless_mut().unwrap().encryption =
            Some("mlkem768x25519plus.native.1rtt.key".into());
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("with VLESS Encryption")
        );
    }

    #[test]
    fn test_validate_rejects_reserved_builtin_names_and_protocols() {
        for (name, protocol) in [
            ("direct", crate::types::NodeProtocol::Socks5),
            ("block", crate::types::NodeProtocol::Socks5),
            ("web-proxy", crate::types::NodeProtocol::Direct),
            ("web-proxy", crate::types::NodeProtocol::Block),
        ] {
            let outbound = match protocol {
                crate::types::NodeProtocol::Socks5 => {
                    crate::node::OutboundConfig::Socks5(Default::default())
                }
                crate::types::NodeProtocol::Direct => crate::node::OutboundConfig::Direct,
                crate::types::NodeProtocol::Block => crate::node::OutboundConfig::Block,
                _ => unreachable!(),
            };
            let mut config = Config::default();
            config.nodes.push(crate::node::Node {
                name: name.into(),
                address: "1.2.3.4:8080".into(),
                outbound,
                ..Default::default()
            });
            let err = config.validate().unwrap_err();
            assert!(
                err.to_string().contains("reserved for the built-in"),
                "{name}/{protocol:?} must be rejected: {err}"
            );
        }
    }

    #[test]
    fn test_validate_rejects_derived_id_conflicts() {
        let node = |name: &str| {
            let mut n =
                crate::node::Node::from_share_link("trojan://secret@example.com:443").unwrap();
            n.name = name.into();
            n
        };
        let mut config = Config::default();
        config.nodes.push(node("alpha"));
        config.nodes.push(node("beta"));
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("'alpha' and 'beta'"),
            "conflict error must name both nodes: {err}"
        );
        // A credential change breaks the tie.
        config.nodes[1].trojan_mut().unwrap().password = Some("other".into());
        config.nodes[1].id = config.nodes[1].derive_id();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_ensure_builtin_nodes_injects_direct_and_block_once() {
        let mut config = Config::default();
        assert!(!config.nodes.iter().any(|n| n.name == "direct"));
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].name, "direct");
        assert_eq!(config.nodes[0].id, DIRECT_NODE_ID);
        assert_eq!(
            config.nodes[0].protocol(),
            crate::types::NodeProtocol::Direct
        );
        assert_eq!(config.nodes[1].name, "block");
        assert_eq!(config.nodes[1].id, BLOCK_NODE_ID);
        assert_eq!(
            config.nodes[1].protocol(),
            crate::types::NodeProtocol::Block
        );
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 2);
        assert!(config.validate().is_ok(), "built-ins stay valid");
    }

    #[test]
    fn test_builtin_node_resolves_registered_or_fresh() {
        let mut config = Config::default();
        let fresh = config.builtin_node("direct").unwrap();
        assert_eq!(fresh.id, DIRECT_NODE_ID);
        assert!(config.builtin_node("proxy").is_none());
        let mut registered = Config::builtin_block_node();
        registered.subscription_id = Some(uuid::Uuid::new_v4());
        config.nodes.push(registered.clone());
        assert_eq!(
            config.builtin_node("block").unwrap().subscription_id,
            registered.subscription_id,
            "a registered built-in wins over the fresh definition"
        );
    }

    #[test]
    fn test_ensure_local_direct_rules_injects_refreshes_and_is_idempotent() {
        let mut config = Config::default();
        config.global.wan_interface =
            vec!["lo".to_string(), "definitely-not-an-iface0".to_string()];
        assert!(config.ensure_local_direct_rules());

        let injected: Vec<_> = config
            .routing
            .rules
            .iter()
            .filter(|r| r.name.starts_with("__local_direct_"))
            .collect();
        // lo carries 127.0.0.1 and ::1 (host scope) on every Linux host.
        assert!(
            injected
                .iter()
                .any(|r| r.condition.ip == vec!["127.0.0.1/32".to_string()]),
            "loopback v4 must be injected: {injected:?}"
        );
        assert!(injected.iter().all(|r| r.must));
        assert!(
            injected
                .iter()
                .all(|rule| rule.outbound.as_str() == "direct")
        );

        let count = config.routing.rules.len();
        assert!(!config.ensure_local_direct_rules());
        assert_eq!(config.routing.rules.len(), count, "must be idempotent");

        config.global.wan_interface = vec!["definitely-not-an-iface0".to_string()];
        assert!(config.ensure_local_direct_rules());
        assert!(
            config
                .routing
                .rules
                .iter()
                .all(|rule| !rule.name.starts_with("__local_direct_")),
            "stale generated rules must be removed"
        );
    }

    fn test_node(name: &str) -> crate::node::Node {
        let mut node =
            crate::node::Node::from_share_link("trojan://secret@example.com:443").unwrap();
        node.name = name.into();
        node
    }

    fn rule_to(outbound: &str) -> crate::routing::RoutingRule {
        crate::routing::RoutingRule {
            name: String::new(),
            condition: crate::routing::RoutingCondition::default(),
            outbound: crate::routing::RoutingOutbound::Simple(outbound.into()),
            priority: 0,
            must: false,
            mark: 0,
        }
    }

    #[test]
    fn test_validate_rejects_bare_node_outbounds() {
        let mut config = Config::default();
        config.nodes.push(test_node("vn"));

        config.routing.rules.push(rule_to("vn"));
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("outbound 'vn' is a node, not a group; wrap it in a group (e.g. filter: name('vn')) or reference a group"),
            "{err}"
        );

        config.routing.rules.clear();
        config.routing.default_outbound = "vn".into();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("fallback 'vn' is a node, not a group; wrap it in a group (e.g. filter: name('vn')) or reference a group"),
            "{err}"
        );
    }

    #[test]
    fn test_validate_accepts_group_and_builtin_outbounds() {
        let mut config = Config::default();
        config.nodes.push(test_node("vn"));
        config.groups.push(crate::group::Group {
            name: "proxy".into(),
            ..Default::default()
        });
        for outbound in ["proxy", "direct", "block"] {
            config.routing.rules = vec![rule_to(outbound)];
            config.routing.default_outbound = outbound.into();
            assert!(config.validate().is_ok(), "outbound '{outbound}' must pass");
        }
    }

    #[test]
    fn test_validate_rejects_unknown_outbounds() {
        let mut config = Config::default();
        config.routing.rules.push(rule_to("missing"));
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains(
                "unknown outbound 'missing' (expected a group name, 'direct', or 'block')"
            ),
            "{err}"
        );

        config.routing.rules.clear();
        config.routing.default_outbound = "missing".into();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains(
                "unknown fallback 'missing' (expected a group name, 'direct', or 'block')"
            ),
            "{err}"
        );
    }

    #[test]
    fn test_validate_rejects_node_group_name_collision() {
        let mut config = Config::default();
        config.nodes.push(test_node("dup"));
        config.groups.push(crate::group::Group {
            name: "dup".into(),
            ..Default::default()
        });
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("name 'dup' is defined as both a node and a group; rename one of them"),
            "{err}"
        );
    }
}
