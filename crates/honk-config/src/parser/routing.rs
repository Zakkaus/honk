use super::lexer::Span;
use super::read::Text;
use super::{Block, ParserDiagnostics, normalize_geosite_code, read, strip_tag_arg};
use crate::diagnostic::{SettingPath, Severity};
use crate::error::{DetailedConfigError, ErrorCategory};
use crate::routing::{RoutingCondition, RoutingConfig, RoutingRule};

/// A window over physical source pieces, including gaps owned by comments.
#[derive(Clone, Copy)]
struct Expression<'p, 'd, 'a> {
    pieces: &'p [Text<'d, 'a>],
    span: Span,
}

impl<'p, 'd, 'a> Expression<'p, 'd, 'a> {
    fn new(pieces: &'p [Text<'d, 'a>]) -> Self {
        Self {
            pieces,
            span: Span {
                end: pieces.last().unwrap().span.end,
                ..pieces[0].span
            },
        }
    }

    fn sub(self, start: usize, end: usize) -> Self {
        Self {
            span: Span {
                start,
                end,
                ..self.span
            },
            ..self
        }
    }

    fn parts(self) -> impl DoubleEndedIterator<Item = Text<'d, 'a>> + 'p {
        self.pieces.iter().filter_map(move |piece| {
            let start = piece.span.start.max(self.span.start);
            let end = piece.span.end.min(self.span.end);
            (start < end).then_some(Text {
                span: Span {
                    start,
                    end,
                    ..piece.span
                },
                ..*piece
            })
        })
    }

    fn trim(self) -> Self {
        let mut parts = self
            .parts()
            .map(Text::trim)
            .filter(|part| !part.raw().is_empty());
        if let Some(first) = parts.next() {
            let end = parts.next_back().unwrap_or(first).span.end;
            self.sub(first.span.start, end)
        } else {
            self.sub(self.span.start, self.span.start)
        }
    }

    fn is_empty(self) -> bool {
        self.span.start == self.span.end
    }

    fn starts_with(self, prefix: &str) -> bool {
        self.parts()
            .next()
            .is_some_and(|part| part.raw().starts_with(prefix))
    }

    fn find(self, delimiter: &str) -> Option<usize> {
        self.parts()
            .find_map(|part| part.find(delimiter).map(|offset| part.span.start + offset))
    }

    fn split(self, delimiter: &'p str) -> impl Iterator<Item = Self> + 'p {
        let mut remaining = Some(self);
        std::iter::from_fn(move || {
            let text = remaining.take()?;
            if let Some(offset) = text.find(delimiter) {
                remaining = Some(text.sub(offset + delimiter.len(), text.span.end));
                Some(text.sub(text.span.start, offset).trim())
            } else {
                Some(text.trim())
            }
        })
    }

    fn parentheses(self) -> impl Iterator<Item = (usize, u8)> + 'p {
        self.parts().flat_map(|part| {
            part.raw()
                .bytes()
                .enumerate()
                .filter_map(move |(offset, byte)| {
                    let position = part.span.start + offset;
                    (matches!(byte, b'(' | b')')
                        && !part
                            .tokens
                            .iter()
                            .flat_map(|token| &token.quoted)
                            .any(|quote| quote.start <= position && position < quote.end))
                    .then_some((position, byte))
                })
        })
    }

    fn display(self) -> String {
        let mut output = String::new();
        for part in self
            .parts()
            .map(Text::trim)
            .filter(|part| !part.raw().is_empty())
        {
            let raw = part.raw();
            // Preserve the existing complex-rule display across continuation lines.
            if !output.is_empty() && !raw.starts_with([')', ',']) {
                output.push(' ');
            }
            output.push_str(raw);
        }
        output
    }

    fn value(self) -> String {
        let text = self.trim();
        let mut parts = text.parts();
        match (parts.next(), parts.next()) {
            (Some(part), None) => part.unquote().raw().to_owned(),
            _ => text.display(),
        }
    }

    fn warn_glued_hash(self, diagnostics: &mut ParserDiagnostics<'_>) {
        for part in self.parts() {
            part.warn_glued_hash(diagnostics);
        }
    }

    fn error(self, code: &'static str, message: &'static str, index: usize) -> DetailedConfigError {
        let mut diagnostic =
            self.pieces[0]
                .source
                .diagnostic(self.span, Severity::Error, code, message);
        diagnostic.setting = SettingPath::new("routing").field("rules").index(index);
        diagnostic.entry_index = Some(index);
        diagnostic.terminal = true;
        DetailedConfigError {
            category: ErrorCategory::Parse,
            diagnostic: Box::new(diagnostic),
        }
    }
}

pub(super) fn parse_section(
    section: &Block,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<RoutingConfig, crate::ConfigError> {
    let mut config = RoutingConfig::default();
    let lines = read::statements(section);
    let mut start = 0;
    let mut depth = 0usize;
    let mut ordinal = 0;
    for end in 0..lines.len() {
        if start < end && lines[start].span.source != lines[end].span.source {
            return Err(crate::ConfigError::Parse(
                "routing: unterminated parenthesized rule at source boundary".into(),
            ));
        }
        for (_, byte) in Expression::new(&lines[end..=end]).parentheses() {
            if byte == b'(' {
                depth += 1;
            } else {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    crate::ConfigError::Parse("routing: unmatched closing parenthesis".into())
                })?;
            }
        }
        if depth != 0 {
            continue;
        }
        ordinal += 1;
        let statement = Expression::new(&lines[start..=end]).trim();
        start = end + 1;
        diagnostics.entry_text(statement.parts().next().unwrap(), ordinal);
        if let Some(prefix) = ["fallback:", "default:"]
            .into_iter()
            .find(|prefix| statement.starts_with(prefix))
        {
            let value = statement
                .sub(statement.span.start + prefix.len(), statement.span.end)
                .trim();
            value.warn_glued_hash(diagnostics);
            config.default_outbound = value.display();
        } else {
            match parse_routing_rule(statement, config.rules.len(), ordinal, diagnostics) {
                Ok(Some((rule, source))) => {
                    if let Some(source) = source {
                        config.record_complex_rule_source(rule.name.clone(), source);
                    }
                    config.rules.push(rule);
                }
                Ok(None) => {}
                Err(error) => {
                    let legacy = crate::ConfigError::Parse(error.diagnostic.message.to_owned());
                    diagnostics.failure = Some(*error.diagnostic);
                    return Err(legacy);
                }
            }
        }
    }
    if depth != 0 {
        return Err(crate::ConfigError::Parse(
            "routing: unterminated parenthesized rule".into(),
        ));
    }
    Ok(config)
}

fn parse_routing_rule(
    statement: Expression<'_, '_, '_>,
    index: usize,
    ordinal: usize,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Option<(RoutingRule, Option<String>)>, DetailedConfigError> {
    let Some(arrow) = statement.find("->") else {
        return Ok(None);
    };
    let left = statement.sub(statement.span.start, arrow).trim();
    let right = statement.sub(arrow + 2, statement.span.end).trim();
    left.warn_glued_hash(diagnostics);
    right.warn_glued_hash(diagnostics);
    if let Some(offset) = right.find("->") {
        right
            .sub(offset, offset + 2)
            .parts()
            .next()
            .unwrap()
            .notice(
                diagnostics,
                Severity::Warning,
                "legacy-arrow-target",
                "additional arrows remain literal outbound data",
            );
    }
    let mut outbound = right.display();
    let must = outbound.ends_with("(must)");
    if must {
        outbound.truncate(outbound.len() - "(must)".len());
        outbound.truncate(outbound.trim_end().len());
    }
    let mut condition = RoutingCondition::default();
    for matcher in left.split("&&").filter(|matcher| !matcher.is_empty()) {
        parse_route_matcher(&mut condition, matcher, ordinal)?;
    }
    let complex = must || left.find("&&").is_some() || condition.needs_complex_display();
    let rule = RoutingRule {
        name: format!("rule-{index}"),
        condition,
        outbound: crate::routing::RoutingOutbound::Simple(outbound),
        priority: index as u32,
        must,
        mark: 0,
    };
    Ok(Some((rule, complex.then(|| statement.display()))))
}

fn parse_route_matcher(
    condition: &mut RoutingCondition,
    matcher: Expression<'_, '_, '_>,
    ordinal: usize,
) -> Result<(), DetailedConfigError> {
    let negated = matcher.starts_with("!");
    let matcher = if negated {
        matcher.sub(matcher.span.start + 1, matcher.span.end).trim()
    } else {
        matcher
    };
    if matcher.is_empty() {
        return Ok(());
    }
    let mut target = if negated {
        condition.not.fields_mut()
    } else {
        condition.fields_mut()
    };
    for name in [
        "pname",
        "dip",
        "sip",
        "domain",
        "dport",
        "sport",
        "l4proto",
        "ipversion",
        "mac",
        "dscp",
    ] {
        if let Some(args) = parse_call(matcher, name, ordinal)? {
            match name {
                "pname" => target.process_name.extend(args),
                "dip" => parse_ip_args(&args, &mut target),
                "sip" => target.source_ip.extend(args),
                "domain" => parse_domain_args(&args, &mut target),
                "dport" => target.port.extend(args),
                "sport" => target.source_port.extend(args),
                "l4proto" => target.protocol.extend(args),
                "ipversion" => target.ip_version.extend(args),
                "mac" => target.mac.extend(args),
                "dscp" => target.dscp.extend(args),
                _ => unreachable!(),
            }
            return Ok(());
        }
    }
    for prefix in [
        "geosite:", "geoip:", "domain:", "suffix:", "keyword:", "full:", "regex:",
    ] {
        if matcher.starts_with(prefix) {
            let value = matcher
                .sub(matcher.span.start + prefix.len(), matcher.span.end)
                .value();
            match prefix {
                "geosite:" => target.geosite.push(normalize_geosite_code(&value)),
                "geoip:" => target.geo_ip.push(normalize_geosite_code(&value)),
                "domain:" | "suffix:" => target.domain_suffix.push(value),
                "keyword:" => target.domain_keyword.push(value),
                "full:" => target.domain.push(value),
                "regex:" => target.domain_regex.push(value),
                _ => unreachable!(),
            }
            return Ok(());
        }
    }
    Err(matcher.error(
        "unknown-traffic-predicate",
        "unknown traffic predicate",
        ordinal,
    ))
}

fn parse_call(
    matcher: Expression<'_, '_, '_>,
    name: &str,
    ordinal: usize,
) -> Result<Option<Vec<String>>, DetailedConfigError> {
    if !matcher.parts().next().is_some_and(|part| {
        part.raw()
            .strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('('))
    }) {
        return Ok(None);
    }
    let call = matcher.sub(matcher.span.start + name.len(), matcher.span.end);
    let Some((position, _)) = call.parentheses().find(|(_, byte)| *byte == b')') else {
        return Ok(None);
    };
    let trailing = call.sub(position + 1, call.span.end);
    if !trailing.trim().is_empty() {
        if trailing.span.start == trailing.trim().span.start {
            return Err(trailing.trim().error(
                "trailing-matcher-text",
                "matcher call has trailing text",
                ordinal,
            ));
        }
        return Ok(None);
    }
    Ok(Some(
        call.sub(call.span.start + 1, position)
            .split(",")
            .map(Expression::value)
            .filter(|value| !value.is_empty())
            .collect(),
    ))
}

fn parse_domain_args(args: &[String], cond: &mut crate::routing::ConditionFields<'_>) {
    for a in args {
        if let Some(v) = strip_tag_arg(a, "geosite:") {
            cond.geosite.push(normalize_geosite_code(&v));
        } else if let Some(v) = strip_tag_arg(a, "keyword:") {
            cond.domain_keyword.push(v);
        } else if let Some(v) = strip_tag_arg(a, "full:") {
            cond.domain.push(v);
        } else if let Some(v) = strip_tag_arg(a, "regex:") {
            cond.domain_regex.push(v);
        } else if let Some(v) = strip_tag_arg(a, "suffix:") {
            cond.domain_suffix.push(v);
        } else {
            cond.domain_suffix.push(a.clone());
        }
    }
}

fn parse_ip_args(args: &[String], cond: &mut crate::routing::ConditionFields<'_>) {
    for a in args {
        if let Some(v) = strip_tag_arg(a, "geoip:") {
            cond.geo_ip.push(normalize_geosite_code(&v));
        } else {
            cond.ip.push(a.clone());
        }
    }
}
