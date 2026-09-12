pub mod cursor;
mod diagnostics;
mod dns;
mod entries;
mod groups;
pub mod lexer;
mod routing;

mod read;
mod scalars;
mod structure;
use entries::{parse_node_section, parse_subscription_section};
use groups::{parse_group_section, resolve_group_filters_inner};
use scalars::{parse_experimental_section, parse_global_section};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod lexer_tests;

#[cfg(test)]
mod cursor_tests;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use self::diagnostics::ParserDiagnostics;
use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, finish_attempt, report_detailed_diagnostics,
};
use crate::error::DetailedConfigError;
use crate::group::Group;
use crate::node::Node;
use crate::subscription::Subscription;
use crate::{Config, ConfigDiagnostic};
use lexer::quoted_end;
use structure::Block;
enum ParseFailure {
    Legacy(crate::ConfigError),
    Detailed(crate::error::DetailedConfigError),
}

impl From<crate::ConfigError> for ParseFailure {
    fn from(error: crate::ConfigError) -> Self {
        Self::Legacy(error)
    }
}

impl From<crate::error::DetailedConfigError> for ParseFailure {
    fn from(error: crate::error::DetailedConfigError) -> Self {
        Self::Detailed(error)
    }
}

/// Load a dae configuration file, resolving its top-level `include` blocks.
///
/// Include paths are relative to the entry configuration's directory, even
/// when they occur in a nested included file.  Included files must remain
/// below that directory after symlink resolution.
pub fn parse_dae_config_file(path: impl AsRef<Path>) -> Result<Config, crate::ConfigError> {
    let mut diagnostics = Vec::new();
    let result = parse_dae_config_file_with_detailed_diagnostics(path, &mut diagnostics);
    report_detailed_diagnostics(&diagnostics);
    result.map_err(DetailedConfigError::into_legacy)
}

/// One-release data projection; the caller's existing prefix is preserved.
pub fn parse_dae_config_file_with_diagnostics(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Result<Config, crate::ConfigError> {
    let mut detailed = Vec::new();
    let result = parse_dae_config_file_with_detailed_diagnostics(path, &mut detailed);
    diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
    result.map_err(DetailedConfigError::into_legacy)
}

pub fn parse_dae_config_file_with_detailed_diagnostics(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    let result = parse_dae_config_file_attempt(path, diagnostics, &mut false);
    finish_attempt(result, diagnostics)
}

pub(crate) fn parse_dae_config_file_attempt(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    semantic: &mut bool,
) -> Result<Config, DetailedConfigError> {
    let source = DiagnosticSources::new(Some(path.as_ref().to_path_buf())).root();
    let mut sink = ParserDiagnostics::new(diagnostics, source);
    match parse_dae_file_inner(path, &mut sink, semantic) {
        Ok(config) => Ok(config),
        Err(ParseFailure::Detailed(error)) => Err(error),
        Err(ParseFailure::Legacy(error)) => Err(sink.error(error)),
    }
}

fn parse_dae_file_inner(
    path: impl AsRef<Path>,
    diagnostics: &mut ParserDiagnostics<'_>,
    semantic: &mut bool,
) -> Result<Config, ParseFailure> {
    let entry =
        std::fs::canonicalize(path.as_ref()).map_err(|error| ParseFailure::Legacy(error.into()))?;
    let entry_dir = entry.parent().map(Path::to_path_buf).ok_or_else(|| {
        ParseFailure::Legacy(crate::ConfigError::Include(format!(
            "entry configuration '{}' has no parent directory",
            entry.display()
        )))
    })?;
    let mut loader = IncludeLoader {
        entry_dir,
        loaded: HashSet::new(),
        stack: Vec::new(),
        saw_include: false,
        entry_input: String::new(),
    };
    let blocks = match loader.expand_file(&entry, diagnostics) {
        Ok(blocks) => blocks,
        Err(err @ crate::ConfigError::Include(_)) => return Err(ParseFailure::Legacy(err)),
        Err(err) if loader.saw_include => {
            return Err(ParseFailure::Legacy(crate::ConfigError::Include(format!(
                "failed to parse configuration after resolving includes: {err}"
            ))));
        }
        Err(err) => return Err(ParseFailure::Legacy(err)),
    };
    match parse_blocks(blocks, diagnostics) {
        Ok(config) => Ok(config),
        Err(err) => {
            *semantic = loader.saw_include || !is_structured_document(&loader.entry_input);
            match err {
                ParseFailure::Detailed(mut error) if loader.saw_include => {
                    if error.category != crate::error::ErrorCategory::UnsupportedPolicy {
                        error.category = crate::error::ErrorCategory::Include;
                    }
                    Err(ParseFailure::Detailed(error))
                }
                err @ ParseFailure::Detailed(_) => Err(err),
                ParseFailure::Legacy(error) if loader.saw_include => {
                    let mut error = diagnostics.error(error);
                    if error.category != crate::error::ErrorCategory::UnsupportedPolicy {
                        error.category = crate::error::ErrorCategory::Include;
                    }
                    Err(ParseFailure::Detailed(error))
                }
                err => Err(err),
            }
        }
    }
}

fn is_structured_document(input: &str) -> bool {
    // A dae semantic failure is final unless the complete document decodes as
    // a YAML, TOML or JSON mapping containing at least one known Config root.
    use crate::config::CONFIG_FIELDS;

    serde_yaml::from_str::<serde_yaml::Value>(input).is_ok_and(|value| {
        value.as_mapping().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| key.as_str().is_some_and(|key| CONFIG_FIELDS.contains(&key)))
        })
    }) || toml::from_str::<toml::Value>(input).is_ok_and(|value| {
        value.as_table().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| CONFIG_FIELDS.contains(&key.as_str()))
        })
    }) || serde_json::from_str::<serde_json::Value>(input).is_ok_and(|value| {
        value.as_object().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| CONFIG_FIELDS.contains(&key.as_str()))
        })
    })
}

struct IncludeLoader {
    entry_dir: PathBuf,
    // dae treats a repeated include as a circular include too.  Keep that
    // behavior, but canonical paths also prevent symlink aliases escaping it.
    loaded: HashSet<PathBuf>,
    stack: Vec<PathBuf>,
    saw_include: bool,
    entry_input: String,
}

impl IncludeLoader {
    fn expand_file(
        &mut self,
        path: &Path,
        diagnostics: &mut ParserDiagnostics<'_>,
    ) -> Result<Vec<Block>, crate::ConfigError> {
        if !self.loaded.insert(path.to_path_buf()) {
            let mut chain = self
                .stack
                .iter()
                .map(|entry| entry.display().to_string())
                .collect::<Vec<_>>();
            chain.push(path.display().to_string());
            return Err(crate::ConfigError::Include(format!(
                "circular or duplicate include is not allowed: {}",
                chain.join(" -> ")
            )));
        }

        let parent = diagnostics.source();
        let source = if self.stack.is_empty() {
            parent
        } else {
            parent
                .sources()
                .add(Some(path.to_path_buf()), Some(parent.index()))
        };
        diagnostics.set_source(source.clone());
        self.stack.push(path.to_path_buf());
        let result = (|| {
            let input = std::fs::read_to_string(path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to read configuration '{}': {err}",
                    path.display()
                ))
            })?;
            let roots = structure::scan_readers(&input, diagnostics, &mut self.saw_include);
            if self.stack.len() == 1 && !matches!(&roots, Err(crate::ConfigError::Include(_))) {
                check_dae_input(&input)?;
            }
            let roots = roots?;
            diagnostics.register_blocks(&roots, &source);
            if self.stack.len() == 1 {
                self.entry_input = input;
            }
            let mut blocks = Vec::new();
            let mut patterns = Vec::new();
            for block in roots {
                if block.name == "include" {
                    self.saw_include = true;
                    for segment in &block.segments {
                        patterns.extend(parse_include_body(segment.get(), path)?);
                    }
                } else {
                    blocks.push(block);
                }
            }

            // dae merges an entry's own sections before the sections of its
            // included descendants, regardless of where `include` occurs in
            // that entry.  Appending recursively gives that preorder.
            for pattern in patterns {
                diagnostics.set_source(source.clone());
                for child in self.expand_pattern(&pattern, path)? {
                    diagnostics.set_source(source.clone());
                    blocks.extend(self.expand_file(&child, diagnostics)?);
                }
            }
            Ok(blocks)
        })();
        self.stack.pop();
        result
    }

    fn expand_pattern(
        &self,
        pattern: &str,
        source: &Path,
    ) -> Result<Vec<PathBuf>, crate::ConfigError> {
        let pattern_path = Path::new(pattern);
        let pattern = if pattern_path.is_absolute() {
            pattern_path.to_path_buf()
        } else {
            self.entry_dir.join(pattern_path)
        };
        // `glob` gives `**` recursive semantics while dae's filepath.Glob
        // treats it as an ordinary same-component wildcard.  Normalize the
        // one divergent form before matching.
        let pattern = normalize_dae_glob_pattern(&pattern);
        let pattern_display = pattern.display().to_string();
        let mut matches = glob::glob(&pattern_display)
            .map_err(|err| {
                crate::ConfigError::Include(format!(
                    "invalid include pattern '{}' in '{}': {err}",
                    pattern_display,
                    source.display()
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to expand include pattern '{}' in '{}': {err}",
                    pattern_display,
                    source.display()
                ))
            })?;
        matches.sort();

        let mut files = Vec::new();
        for path in matches {
            if path.extension().and_then(|ext| ext.to_str()) != Some("dae") {
                continue;
            }
            let metadata = std::fs::metadata(&path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to inspect included path '{}': {err}",
                    path.display()
                ))
            })?;
            if metadata.is_dir() {
                continue;
            }

            let path = std::fs::canonicalize(&path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to resolve included path '{}': {err}",
                    path.display()
                ))
            })?;
            if !path.starts_with(&self.entry_dir) {
                return Err(crate::ConfigError::Include(format!(
                    "included path '{}' is outside entry configuration directory '{}'",
                    path.display(),
                    self.entry_dir.display()
                )));
            }
            files.push(path);
        }
        Ok(files)
    }
}

fn normalize_dae_glob_pattern(pattern: &Path) -> PathBuf {
    // honk runs on Linux, where `/` is both the dae and native separator.
    let normalized = pattern
        .to_string_lossy()
        .split('/')
        .map(|component| if component == "**" { "*" } else { component })
        .collect::<Vec<_>>()
        .join("/");
    PathBuf::from(normalized)
}

fn parse_include_body(
    segment: cursor::Segment<'_, '_>,
    source: &Path,
) -> Result<Vec<String>, crate::ConfigError> {
    let mut patterns = Vec::new();
    let Some(mut body) = segment.body() else {
        return Ok(patterns);
    };
    while body.next() {
        let entry = body.next_segment().expect("include pattern or block");
        if entry.body().is_some() {
            return Err(crate::ConfigError::Include(format!(
                "include section in '{}' accepts only file patterns",
                source.display()
            )));
        }
        let raw = entry.source().raw(entry.header_span());
        let bytes = raw.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index == bytes.len() {
                break;
            }
            if matches!(bytes[index], b'{' | b'}') {
                return Err(crate::ConfigError::Include(format!(
                    "include section in '{}' accepts only file patterns",
                    source.display()
                )));
            }
            // Adjacent quoted paths remain file-reader syntax, not lexical boundaries.
            let value = if matches!(bytes[index], b'\'' | b'"') {
                let start = index + 1;
                let end = quoted_end(bytes, index).ok_or_else(|| {
                    crate::ConfigError::Include(format!(
                        "unterminated quoted include path in '{}'",
                        source.display()
                    ))
                })?;
                index = end;
                &raw[start..end - 1]
            } else {
                let start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && !matches!(bytes[index], b'{' | b'}')
                {
                    index += 1;
                }
                &raw[start..index]
            };
            if value.is_empty() {
                return Err(crate::ConfigError::Include(format!(
                    "empty include path in '{}'",
                    source.display()
                )));
            }
            patterns.push(value.to_owned());
        }
    }
    Ok(patterns)
}

pub fn parse_dae_config(input: &str) -> Result<Config, crate::ConfigError> {
    let mut diagnostics = Vec::new();
    let result = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics);
    report_detailed_diagnostics(&diagnostics);
    result.map_err(DetailedConfigError::into_legacy)
}

/// One-release data projection; never logs or exposes arbitrary input values.
pub fn parse_dae_config_with_diagnostics(
    input: &str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Result<Config, crate::ConfigError> {
    let mut detailed = Vec::new();
    let result = parse_dae_config_with_detailed_diagnostics(input, &mut detailed);
    diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
    result.map_err(DetailedConfigError::into_legacy)
}

pub fn parse_dae_config_with_detailed_diagnostics(
    input: &str,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    let source = DiagnosticSources::new(None).root();
    let mut sink = ParserDiagnostics::new(diagnostics, source.clone());
    let result: Result<Config, ParseFailure> = (|| {
        check_dae_input(input)?;
        let blocks = structure::scan_readers(input, &mut sink, &mut false)?;
        sink.register_blocks(&blocks, &source);
        parse_blocks(blocks, &mut sink)
    })();
    let result = result.map_err(|error| match error {
        ParseFailure::Detailed(error) => error,
        ParseFailure::Legacy(error) => sink.error(error),
    });
    finish_attempt(result, sink.output)
}

fn check_dae_input(input: &str) -> Result<(), crate::ConfigError> {
    let mut has_open = false;
    let mut has_close = false;
    for line in input.lines().map(str::trim_start) {
        if !line.starts_with('#') {
            has_open |= line.contains('{');
            has_close |= line.contains('}');
        }
    }
    if !has_open || !has_close {
        return Err(crate::ConfigError::Parse("not a dae config file".into()));
    }
    Ok(())
}

fn parse_blocks(
    blocks: Vec<Block>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Config, ParseFailure> {
    let mut sections = Vec::<Block>::new();
    let mut indices = HashMap::<String, usize>::new();
    for block in blocks {
        if let Some(&index) = indices.get(&block.name) {
            sections[index].items.extend(block.items);
            sections[index].segments.extend(block.segments);
        } else {
            indices.insert(block.name.clone(), sections.len());
            sections.push(block);
        }
    }

    let canonical_nfqueue_present = sections
        .iter()
        .filter(|section| section.name == "global")
        .any(scalars::nfqueue_present);
    let mut config = Config::default();

    for section in &sections {
        diagnostics.at_section(section, &[]);
        match section.name.as_str() {
            "global" => config.global = parse_global_section(section, diagnostics)?,
            "dns" => config.dns = dns::parse_section(section, diagnostics)?,
            "routing" => config.routing = routing::parse_section(section, diagnostics)?,
            "node" => {
                for node in parse_node_section(section, diagnostics)? {
                    config.nodes.push(node);
                }
            }
            "group" => {
                for group in parse_group_section(section, diagnostics)? {
                    config.groups.push(group);
                }
            }
            "subscription" => {
                for sub in parse_subscription_section(section, diagnostics)? {
                    config.subscriptions.push(sub);
                }
            }
            "experimental" => {
                config.experimental = parse_experimental_section(section, diagnostics)?;
            }
            _ => {}
        }
    }
    config.apply_legacy_nfqueue(canonical_nfqueue_present);

    for group in &mut config.groups {
        if group.policy == crate::node::GroupPolicy::URLTest {
            group.tolerance = config.global.check_tolerance_ms;
        }
    }

    resolve_group_filters_inner(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
        Some(diagnostics),
    );

    Ok(config)
}

/// Resolve group filters into concrete node UUIDs.
///
/// Each `filter:` line is OR-ed. Predicates joined by `&&` within one line
/// are AND-ed and may be negated with `!`. Supported predicates are
/// `name(...)` and dae-compatible `subtag(...)`; both accept exact values,
/// `keyword:`, and `regex:` arguments.
///
/// `group('tag')` entries are not node filters — the dae parser routes them
/// into `Group.groups` at parse time.
pub fn resolve_group_filters(groups: &mut [Group], nodes: &[Node], subscriptions: &[Subscription]) {
    // Runtime re-resolution: the filters were reported when the config was parsed.
    resolve_group_filters_inner(groups, nodes, subscriptions, None);
}

fn unquote_filter_argument(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        ) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[expect(dead_code, reason = "Retained for C13 last-caller retirement")]
fn find_unquoted(input: &str, delimiter: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            index = quoted_end(bytes, index)?;
        } else if bytes[index..].starts_with(delimiter.as_bytes()) {
            return Some(index);
        } else {
            index += 1;
        }
    }
    None
}

#[expect(dead_code, reason = "Retained for C13 last-caller retirement")]
fn split_unquoted<'a>(input: &'a str, delimiter: &'a str) -> impl Iterator<Item = &'a str> {
    let mut remaining = Some(input);
    std::iter::from_fn(move || {
        let input = remaining.take()?;
        if let Some(index) = find_unquoted(input, delimiter) {
            remaining = Some(&input[index + delimiter.len()..]);
            Some(&input[..index])
        } else {
            Some(input)
        }
    })
}

#[expect(dead_code, reason = "Retained for C13 last-caller retirement")]
fn extract_fn_args(expr: &str, fn_name: &str) -> Option<Vec<String>> {
    let body = expr.strip_prefix(fn_name)?.strip_prefix('(')?;
    let end = find_unquoted(body, ")")?;
    if !body[end + 1..].trim().is_empty() {
        return None;
    }
    let args = &body[..end];
    Some(
        split_unquoted(args, ",")
            .map(unquote_filter_argument)
            .filter(|arg| !arg.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Strip a `prefix:` marker from a route argument.  Dae syntax allows spaces
/// after the colon (`geosite: cn`), and the value may carry its own quotes.
fn strip_tag_arg(arg: &str, prefix: &str) -> Option<String> {
    arg.strip_prefix(prefix)
        .map(|value| unquote_filter_argument(value).to_string())
}

/// Normalize a geosite list name.
fn normalize_geosite_code(code: &str) -> String {
    // Keep the code verbatim: `@attr` is an attribute filter applied at
    // expansion time (honk-core routing/geo.rs), not part of the category
    // name — remapping it to `-` silently mismatched into a nonexistent
    // category.
    code.trim().to_string()
}

fn parse_checked_bool(s: &str, setting: &str) -> Result<bool, crate::ConfigError> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(crate::ConfigError::Parse(format!(
            "invalid boolean for {setting}: {s}"
        ))),
    }
}

/// Keep `fallback` when `parsed` is `None` and record why. For settings whose
/// unparseable value does not justify rejecting the configuration.
fn lenient<T>(
    parsed: Option<T>,
    fallback: T,
    diagnostics: &mut ParserDiagnostics<'_>,
    diagnostic: impl FnOnce() -> ConfigDiagnostic,
) -> T {
    match parsed {
        Some(value) => value,
        None => {
            diagnostics.push(diagnostic());
            fallback
        }
    }
}

/// Lenient boolean for dae settings honk does not reject. Recognised spellings are dae's
/// (`true/t/1/y/yes/on`, `false/f/0/n/no/off`, case-insensitive) and produce no
/// diagnostic; `t` and `y` still yield false, a divergence recorded in the lab notes.
fn lenient_bool(value: &str, setting: &str, diagnostics: &mut ParserDiagnostics<'_>) -> bool {
    let lowered = value.to_lowercase();
    match lowered.as_str() {
        "true" | "yes" | "1" | "on" => true,
        "false" | "f" | "0" | "n" | "no" | "off" | "t" | "y" => false,
        _ => {
            diagnostics.push(ConfigDiagnostic {
                setting: setting.to_string(),
                value: value.to_string(),
                message: "value is not a boolean spelling honk recognises; using fallback false"
                    .to_string(),
            });
            false
        }
    }
}

fn parse_hex_or_dec(s: &str) -> Option<u32> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).ok().or_else(|| s.parse().ok())
}

// Invalid URLTest tolerance or compatibility sniffing timeout does not justify
// rejecting the configuration; keep the documented default. Refuse non-finite
// and negative values rather than letting `as u64` saturate to `u64::MAX` or zero.
fn lenient_duration_ms(
    value: &str,
    setting: &str,
    default: u64,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> u64 {
    lenient(
        crate::types::parse_duration_ms(value),
        default,
        diagnostics,
        || ConfigDiagnostic {
            setting: setting.to_string(),
            value: value.to_string(),
            message: format!(
                "duration is not milliseconds, `ms` or `s`; keeping the default ({default}ms)"
            ),
        },
    )
}

fn parse_ip_prefer(s: &str) -> Option<crate::dns::DnsStrategy> {
    use crate::dns::DnsStrategy;
    // dae `ipversion_prefer` is a *preference*, not an only-mode: 4/6 map to
    // the prefer variants (other family still answered when it alone exists),
    // and 0 is dae's "no preference", the same as omitting the setting.
    match s.parse::<i32>() {
        Ok(0) => Some(DnsStrategy::Both),
        Ok(4) => Some(DnsStrategy::PreferIpv4),
        Ok(6) => Some(DnsStrategy::PreferIpv6),
        _ => None,
    }
}
