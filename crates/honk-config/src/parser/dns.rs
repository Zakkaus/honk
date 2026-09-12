use std::collections::HashMap;

use super::cursor::Segment;
use super::read::{self, Text};
use super::scalars;
use super::{
    Block, ParserDiagnostics, extract_fn_args, find_unquoted, lenient, normalize_geosite_code,
    parse_ip_prefer, split_unquoted, strip_tag_arg,
};
use crate::ConfigDiagnostic;
use crate::diagnostic::{DetailedDiagnostic, SafeValue, SettingPath, Severity};
use crate::dns::DnsConfig;

// Preserve unknown-wrapper traversal until C13 changes that policy.
fn children<'d, 'a>(
    section: &Segment<'d, 'a>,
    recognized: &[&str],
    lines: &mut Vec<Text<'d, 'a>>,
    blocks: &mut Vec<Segment<'d, 'a>>,
) {
    if let Some(mut body) = section.body() {
        while body.next() {
            let child = body.next_segment().expect("DNS statement or block");
            if let Some(header) = read::block_header(&child) {
                if recognized.contains(&header.raw()) {
                    blocks.push(child);
                } else {
                    lines.push(header);
                    children(&child, recognized, lines, blocks);
                }
            } else {
                lines.push(Text::segment(&child));
            }
        }
    }
}
fn terminal_scalar_quote(
    line: Text<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<(), crate::ConfigError> {
    if !line.has_error() {
        return Ok(());
    }
    let Some(index) = diagnostics.output.iter().rposition(|diagnostic| {
        diagnostic.code == "unterminated-quote"
            && diagnostic.source.same_source(&line.source.reference())
            && diagnostic
                .span
                .as_ref()
                .is_some_and(|span| span.start < line.span.end && line.span.start < span.end)
    }) else {
        return Err(crate::ConfigError::Parse(
            "unterminated scalar quote".into(),
        ));
    };
    let mut diagnostic = diagnostics.output.remove(index);
    diagnostic.terminal = true;
    diagnostics.failure = Some(diagnostic);
    Err(crate::ConfigError::Parse(
        "unterminated scalar quote".into(),
    ))
}

fn raw_fields<'d>(
    lines: Vec<Text<'d, 'static>>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<(HashMap<&'d str, Text<'d, 'static>>, Vec<Text<'d, 'static>>), crate::ConfigError> {
    let mut raw = HashMap::new();
    let mut hosts = Vec::new();
    for line in lines {
        terminal_scalar_quote(line, diagnostics)?;
        let Some((key, value)) = line.kv() else {
            continue;
        };
        let key = key.raw();
        diagnostics.register_field(key, value);
        value.warn_glued_hash(diagnostics);
        if key == "use_host" {
            hosts.push(value);
        }
        raw.insert(key, value);
    }
    Ok((raw, hosts))
}

pub(super) fn parse_section(
    section: &Block,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<DnsConfig, crate::ConfigError> {
    diagnostics.at_section(section, &["upstream", "routing", "fixed_domain_ttl"]);
    let mut lines = Vec::new();
    let mut dns_subs = Vec::new();
    for owned in &section.segments {
        children(
            &owned.get(),
            &["upstream", "routing", "fixed_domain_ttl"],
            &mut lines,
            &mut dns_subs,
        );
    }
    let (settings, hosts) = raw_fields(lines, diagnostics)?;
    let mut cfg = DnsConfig::default();
    let mut saw_upstream = false;
    if let Some(bind) = settings.get("bind") {
        cfg.bind = bind.unquote().raw().to_owned();
        cfg.bind_endpoint()
            .map_err(|error| crate::ConfigError::Parse(error.to_string()))?;
    }
    if settings.contains_key("hosts_file") {
        return Err(crate::ConfigError::Parse(
            "dns.hosts_file was removed; use one or more use_host paths".into(),
        ));
    }
    for value in hosts {
        crate::dns::push_host_source(&mut cfg.hosts, value.unquote().raw());
    }
    if let Some(value) = settings.get("client_subnet") {
        cfg.client_subnet = value.unquote().raw().to_owned();
        cfg.client_subnet_mode()
            .map_err(|error| crate::ConfigError::Parse(error.to_string()))?;
    }
    if let Some(v) = settings.get("ipversion_prefer") {
        let value = v.unquote().raw();
        cfg.strategy = lenient(
            parse_ip_prefer(value),
            crate::dns::DnsStrategy::Both,
            diagnostics,
            || {
                ConfigDiagnostic {
                setting: "dns.ipversion_prefer".to_string(),
                value: value.to_string(),
                message: "honk could not parse the preference as decimal 0, 4 or 6; using fallback: no preference"
                    .to_string(),
            }
            },
        );
    }
    if settings.contains_key("optimistic_cache") {
        cfg.cache.enabled = scalars::bool_value(
            &settings,
            "optimistic_cache",
            "dns.optimistic_cache",
            diagnostics,
        );
    }
    if let Some(v) = settings.get("optimistic_cache_ttl") {
        let value = v.unquote().raw();
        cfg.cache.ttl = lenient(value.parse().ok(), 60, diagnostics, || {
            ConfigDiagnostic {
            setting: "dns.optimistic_cache_ttl".to_string(),
            value: value.to_string(),
            message: "honk could not parse this value as an unsigned decimal integer in range; using fallback 60"
                .to_string(),
        }
        });
    }
    if let Some(v) = settings.get("optimistic_stale_reply_ttl") {
        let value = v.unquote().raw();
        cfg.cache.stale_reply_ttl = lenient(value.parse().ok(), 30, diagnostics, || {
            ConfigDiagnostic {
                setting: "dns.optimistic_stale_reply_ttl".to_string(),
                value: value.to_string(),
                message: "honk could not parse this value as an unsigned decimal integer in range; using fallback 30"
                    .to_string(),
            }
        });
    }
    if let Some(v) = settings.get("max_cache_size") {
        let value = v.unquote().raw();
        cfg.cache.max_size = lenient(value.parse().ok(), 10000, diagnostics, || {
            ConfigDiagnostic {
            setting: "dns.max_cache_size".to_string(),
            value: value.to_string(),
            message: "honk could not parse this value as an unsigned decimal integer in range; using fallback 10000"
                .to_string(),
        }
        });
    }

    for sub in dns_subs {
        match read::block_header(&sub).unwrap().raw() {
            "upstream" => {
                if !saw_upstream {
                    cfg.upstream.clear();
                    saw_upstream = true;
                }
                cfg.upstream.extend(parse_dns_upstreams(&sub, diagnostics));
            }
            "routing" => {
                let mut blocks = Vec::new();
                children(&sub, &["request", "response"], &mut Vec::new(), &mut blocks);
                for req in blocks
                    .iter()
                    .filter(|block| read::block_header(block).unwrap().raw() == "request")
                {
                    let req_lines = read::child_statements(req);
                    let has_fallback = req_lines.iter().any(|line| {
                        line.raw().starts_with("fallback:") || line.raw().starts_with("default:")
                    });
                    let request = parse_dns_request_routing(
                        req_lines
                            .into_iter()
                            .filter(|line| !line.has_error())
                            .map(Text::raw),
                        diagnostics,
                    );
                    cfg.routing.request.rules.extend(request.rules);
                    if !has_fallback {
                        continue;
                    }
                    cfg.routing.request.fallback = request.fallback;
                    // Sync legacy fallback for callers that only look there.
                    if let crate::dns::DnsRequestAction::Upstream(ref name) =
                        cfg.routing.request.fallback
                    {
                        cfg.routing.fallback = name.clone();
                    }
                }
                for resp in blocks
                    .iter()
                    .filter(|block| read::block_header(block).unwrap().raw() == "response")
                {
                    let resp_lines = read::child_statements(resp);
                    let has_fallback = resp_lines.iter().any(|line| {
                        line.raw().starts_with("fallback:") || line.raw().starts_with("default:")
                    });
                    let response = parse_dns_response_routing(
                        resp_lines
                            .into_iter()
                            .filter(|line| !line.has_error())
                            .map(Text::raw),
                        diagnostics,
                    );
                    cfg.routing.response.rules.extend(response.rules);
                    if has_fallback {
                        cfg.routing.response.fallback = response.fallback;
                    }
                }
            }
            "fixed_domain_ttl" => {
                cfg.fixed_domain_ttl
                    .extend(parse_fixed_domain_ttl(&sub, diagnostics));
            }
            _ => {}
        }
    }

    Ok(cfg)
}

fn trailing_comment<'d, 'a>(line: Text<'d, 'a>) -> Option<Text<'d, 'a>> {
    // The dispenser excludes trivia; only the gap immediately after its last token matters.
    let rest = &line.source.text()[line.span.end..];
    let gap = rest.len() - rest.trim_start_matches([' ', '\t']).len();
    rest[gap..].starts_with('#').then(|| Text {
        span: line
            .source
            .span(line.span.end + gap, line.span.end + gap + 1),
        ..line
    })
}

fn parse_dns_upstreams(
    section: &Segment<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Vec<crate::dns::DnsUpstream> {
    let mut upstreams = Vec::new();
    for (index, line) in read::child_statements(section).into_iter().enumerate() {
        if line.has_error() {
            continue;
        }
        let Some((name, rest)) = line.kv() else {
            continue;
        };
        diagnostics.entry_text(line, index + 1);
        if let Some(comment) = trailing_comment(line) {
            comment.notice(
                diagnostics,
                Severity::Warning,
                "legacy-upstream-comment",
                "upstream comments start at an unquoted token-head `#`",
            );
        }
        let separator = rest
            .find("->")
            .map(|offset| (offset, 2))
            .or_else(|| rest.find("outbound:").map(|offset| (offset, 9)));
        let legacy_separator = rest
            .raw()
            .find("->")
            .map(|offset| (offset, 2))
            .or_else(|| rest.raw().find("outbound:").map(|offset| (offset, 9)));
        if let Some((offset, length)) = legacy_separator.filter(|old| Some(*old) != separator) {
            rest.sub(offset, offset + length).notice(
                diagnostics,
                Severity::Warning,
                "legacy-upstream-separator",
                "quoted URI separators are data; put the detour outside URL quotes",
            );
        }
        let (uri, outbound) = if let Some((offset, length)) = separator {
            let target = rest.sub(offset + length, rest.raw().len()).unquote().raw();
            (
                rest.sub(0, offset).unquote().raw(),
                (length == 9 || !target.is_empty()).then(|| target.to_owned()),
            )
        } else {
            (rest.unquote().raw(), None)
        };
        let (protocol, address) = parse_upstream_uri(uri);
        let (address, explicit_sni) = extract_tls_server_name(address);
        let tls_server_name = explicit_sni.or_else(|| sni_from_upstream_address(&address));
        upstreams.push(crate::dns::DnsUpstream {
            name: name.raw().to_owned(),
            address,
            protocol,
            tls_server_name,
            outbound,
        });
    }
    upstreams
}

fn parse_upstream_uri(uri: &str) -> (crate::types::DnsProtocol, String) {
    let uri = uri.trim();
    if let Some(rest) = uri.strip_prefix("tcp+udp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("udp+tcp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("h3://") {
        (crate::types::DnsProtocol::H3, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("http3://") {
        (crate::types::DnsProtocol::H3, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("quic://") {
        (crate::types::DnsProtocol::Quic, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("https://") {
        (crate::types::DnsProtocol::Https, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("tls://") {
        (crate::types::DnsProtocol::Tls, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("tcp://") {
        (crate::types::DnsProtocol::Tcp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("udp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else {
        (crate::types::DnsProtocol::Udp, uri.to_string())
    }
}

/// Derive a TLS SNI hostname from a stripped upstream address.
///
/// Returns `None` when the host is a bare IP (no SNI needed / not useful).
fn sni_from_upstream_address(address: &str) -> Option<String> {
    let hostport = address.split('/').next().unwrap_or(address);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        hostport
            .rsplit_once(':')
            .map(|(h, p)| {
                // Only treat as host:port when the suffix is numeric.
                if p.chars().all(|c| c.is_ascii_digit()) {
                    h
                } else {
                    hostport
                }
            })
            .unwrap_or(hostport)
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    // Bare IPs do not need (and often cannot use) SNI.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(host.to_string())
}

/// Strip an explicit `tls_server_name=` query parameter from an upstream
/// address, e.g. `tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com`.
/// Needed for IP-literal TLS upstreams whose certificate hostname differs
/// from the dial address. Other query pairs are preserved.
fn extract_tls_server_name(address: String) -> (String, Option<String>) {
    let Some(qpos) = address.find('?') else {
        return (address, None);
    };
    let (base, query) = address.split_at(qpos);
    let mut sni = None;
    let mut kept = Vec::new();
    for pair in query[1..].split('&') {
        if let Some(v) = pair.strip_prefix("tls_server_name=") {
            let v = v.trim();
            if !v.is_empty() {
                sni = Some(v.to_string());
            }
        } else if !pair.is_empty() {
            kept.push(pair);
        }
    }
    let address = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    (address, sni)
}

fn parse_fixed_domain_ttl(
    section: &Segment<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for (index, line) in read::child_statements(section).into_iter().enumerate() {
        if line.has_error() {
            continue;
        }
        let Some((key, value)) = line.kv() else {
            continue;
        };
        diagnostics.entry_text(value, index + 1);
        let extra = value
            .tokens
            .iter()
            .filter(|token| token.span.start < value.span.end && value.span.start < token.span.end)
            .nth(1);
        let scalar = value.unquote();
        let (code, message) = if extra.is_some() {
            (
                "trailing-value",
                "TTL requires exactly one decimal scalar; entry omitted",
            )
        } else if let Ok(ttl) = scalar.raw().parse::<u32>() {
            map.insert(key.unquote().raw().to_owned(), ttl);
            if scalar.span == value.span {
                continue;
            }
            (
                "legacy-ttl-quoting",
                "quoted decimal TTL is accepted; use bare or quoted decimal values",
            )
        } else {
            (
                "invalid-ttl",
                "TTL must be an unsigned 32-bit decimal integer; entry omitted",
            )
        };
        diagnostics.emit(DetailedDiagnostic::warning(
            code,
            diagnostics.source(),
            SettingPath::new("dns")
                .field("fixed_domain_ttl")
                .index(index + 1),
            SafeValue::Ordinal(index + 1),
            message,
        ));
    }
    map
}

fn strip_dns_routing_comment(line: &str) -> &str {
    let line = line.trim();
    // DNS gives // precedence and tests only the first unquoted # for a preceding space.
    if let Some(pos) = find_unquoted(line, "//") {
        &line[..pos]
    } else if let Some(pos) = find_unquoted(line, "#")
        && pos > 0
        && line.as_bytes()[pos - 1] == b' '
    {
        &line[..pos]
    } else {
        line
    }
}

/// Parse `routing.request { ... }` block.
fn parse_dns_request_routing<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> crate::dns::DnsRequestRouting {
    let mut routing = crate::dns::DnsRequestRouting::default();

    for (index, line) in lines.into_iter().enumerate() {
        let ordinal = index + 1;
        diagnostics.entry(line, ordinal);
        let trimmed = strip_dns_routing_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("fallback:") || trimmed.starts_with("default:") {
            let fb = trimmed.split_once(':').unwrap().1.trim();
            routing.fallback = crate::dns::DnsRequestAction::parse(fb);
            continue;
        }

        if let Some(arrow_pos) = find_unquoted(trimmed, "->") {
            let left = trimmed[..arrow_pos].trim();
            let right = trimmed[arrow_pos + 2..].trim();
            let action = crate::dns::DnsRequestAction::parse(right);
            let conditions = parse_dns_conditions(left, false, diagnostics, "request", ordinal);
            if !conditions.is_empty() {
                routing
                    .rules
                    .push(crate::dns::DnsRequestRule { conditions, action });
            }
        }
    }

    routing
}

/// Parse `routing.response { ... }` block.
fn parse_dns_response_routing<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> crate::dns::DnsResponseRouting {
    let mut routing = crate::dns::DnsResponseRouting::default();

    for (index, line) in lines.into_iter().enumerate() {
        let ordinal = index + 1;
        diagnostics.entry(line, ordinal);
        let trimmed = strip_dns_routing_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("fallback:") || trimmed.starts_with("default:") {
            let fb = trimmed.split_once(':').unwrap().1.trim();
            routing.fallback = crate::dns::DnsResponseAction::parse(fb);
            continue;
        }

        if let Some(arrow_pos) = find_unquoted(trimmed, "->") {
            let left = trimmed[..arrow_pos].trim();
            let right = trimmed[arrow_pos + 2..].trim();
            let action = crate::dns::DnsResponseAction::parse(right);
            let conditions = parse_dns_conditions(left, true, diagnostics, "response", ordinal);
            if !conditions.is_empty() {
                routing
                    .rules
                    .push(crate::dns::DnsResponseRule { conditions, action });
            }
        }
    }

    routing
}

/// Parse a chain of `&&`-separated conditions.
fn parse_dns_conditions(
    expr: &str,
    is_response: bool,
    diagnostics: &mut ParserDiagnostics<'_>,
    route_kind: &'static str,
    ordinal: usize,
) -> Vec<crate::dns::DnsCond> {
    let mut conds = Vec::new();

    for part in split_unquoted(expr, "&&") {
        let part = part.trim();
        if part.is_empty() {
            invalid_dns_rule(diagnostics, route_kind, ordinal, "invalid-dns-rule");
            return Vec::new();
        }
        let (not, inner) = if let Some(rest) = part.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, part)
        };

        if let Some(args) = extract_fn_args(inner, "qname") {
            let matchers = parse_dns_qname_args(&args);
            conds.push(crate::dns::DnsCond::Qname { not, matchers });
            continue;
        }

        if let Some(args) = extract_fn_args(inner, "qtype") {
            let types: Option<Vec<u16>> = args
                .iter()
                .flat_map(|argument| argument.split(','))
                .map(crate::dns::parse_qtype_token)
                .collect();
            let Some(types) = types else {
                invalid_dns_rule(diagnostics, route_kind, ordinal, "invalid-qtype");
                return Vec::new();
            };
            conds.push(crate::dns::DnsCond::Qtype { not, types });
            continue;
        }

        if let Some(cidrs) = extract_fn_args(inner, "sip") {
            if !validate_dns_networks(&cidrs, diagnostics, route_kind, ordinal) {
                return Vec::new();
            }
            conds.push(crate::dns::DnsCond::Sip { not, cidrs });
            continue;
        }

        if is_response {
            if let Some(args) = extract_fn_args(inner, "upstream") {
                conds.push(crate::dns::DnsCond::Upstream { not, names: args });
                continue;
            }
            if let Some(args) = extract_fn_args(inner, "ip") {
                let (cidrs, geoip) = parse_dns_ip_args(&args);
                if !validate_dns_networks(&cidrs, diagnostics, route_kind, ordinal) {
                    return Vec::new();
                }
                conds.push(crate::dns::DnsCond::Ip { not, cidrs, geoip });
                continue;
            }
        }

        let code = if inner.starts_with("sub(")
            || inner.starts_with("node(")
            || inner.starts_with("subnode(")
        {
            "unsupported-dns-condition"
        } else {
            "invalid-dns-rule"
        };
        invalid_dns_rule(diagnostics, route_kind, ordinal, code);
        return Vec::new();
    }

    conds
}

fn invalid_dns_rule(
    diagnostics: &mut ParserDiagnostics<'_>,
    route_kind: &'static str,
    ordinal: usize,
    code: &'static str,
) {
    diagnostics.emit(DetailedDiagnostic::warning(
        code,
        diagnostics.source(),
        SettingPath::new("dns")
            .field("routing")
            .field(route_kind)
            .field("rules")
            .index(ordinal),
        SafeValue::Ordinal(ordinal),
        "invalid or unsupported DNS condition; whole rule omitted",
    ));
}

fn validate_dns_networks(
    values: &[String],
    diagnostics: &mut ParserDiagnostics<'_>,
    route_kind: &'static str,
    ordinal: usize,
) -> bool {
    let mut truncated = false;
    for value in values {
        let Some(decoded) = crate::dns::decode_ip_or_cidr(value) else {
            invalid_dns_rule(diagnostics, route_kind, ordinal, "invalid-dns-network");
            return false;
        };
        truncated |= decoded.truncated;
    }
    if truncated {
        diagnostics.emit(DetailedDiagnostic::warning(
            "dns-network-host-bits",
            diagnostics.source(),
            SettingPath::new("dns")
                .field("routing")
                .field(route_kind)
                .field("rules")
                .index(ordinal),
            SafeValue::Ordinal(ordinal),
            "DNS network host bits are truncated to the network prefix",
        ));
    }
    true
}

/// Parse qname(args) into a list of domain matchers.
fn parse_dns_qname_args(args: &[String]) -> Vec<crate::dns::DnsDomainMatcher> {
    let mut matchers = Vec::new();
    for a in args {
        let a = a.trim();
        if a.is_empty() {
            continue;
        }
        if let Some(v) = strip_tag_arg(a, "geosite:") {
            matchers.push(crate::dns::DnsDomainMatcher::Geosite(
                normalize_geosite_code(&v),
            ));
        } else if let Some(v) = strip_tag_arg(a, "keyword:") {
            matchers.push(crate::dns::DnsDomainMatcher::Keyword(v));
        } else if let Some(v) = strip_tag_arg(a, "full:") {
            matchers.push(crate::dns::DnsDomainMatcher::Full(v));
        } else if let Some(v) = strip_tag_arg(a, "regex:") {
            matchers.push(crate::dns::DnsDomainMatcher::Regex(v));
        } else if let Some(v) = strip_tag_arg(a, "suffix:") {
            matchers.push(crate::dns::DnsDomainMatcher::Suffix(v));
        } else {
            // Bare argument → suffix (dae compatible)
            matchers.push(crate::dns::DnsDomainMatcher::Suffix(a.to_string()));
        }
    }
    matchers
}

/// Parse ip(...) args into (cidrs, geoip_codes).
fn parse_dns_ip_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut cidrs = Vec::new();
    let mut geoip = Vec::new();
    for a in args {
        let a = a.trim();
        if let Some(v) = strip_tag_arg(a, "geoip:") {
            geoip.push(v.to_lowercase());
        } else {
            cidrs.push(a.to_string());
        }
    }
    (cidrs, geoip)
}
