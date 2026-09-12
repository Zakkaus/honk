use super::lexer::quoted_end;
use std::ops::Range;
use std::sync::Arc;

use super::cursor::{Document, Segment};
use super::diagnostics::ParserDiagnostics;
use super::lexer::{Source, Span, TokenKind};

use crate::{ConfigDiagnostic, ConfigError};

#[derive(Debug, PartialEq, Eq)]
pub struct Block {
    pub name: String,
    pub items: Vec<Item>,
    pub line: usize,
    pub header: String,
    pub closing: String,
    pub segments: Vec<OwnedSegment>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    Statement(String, usize),
    Block(Block),
}

#[derive(Debug, Clone)]
pub struct OwnedSegment {
    document: Arc<Document<'static>>,
    range: Range<usize>,
}

impl OwnedSegment {
    pub fn get(&self) -> Segment<'_, 'static> {
        self.document.segment(self.range.clone())
    }
}

impl PartialEq for OwnedSegment {
    fn eq(&self, other: &Self) -> bool {
        self.range == other.range && self.document.source().text() == other.document.source().text()
    }
}
impl Eq for OwnedSegment {}

impl Block {
    /// Return the ambient lines represented by this block for a consumer that
    /// recognises the named blocks in `recognised`.
    pub fn lines_except<'a>(&'a self, recognised: &[&str]) -> Vec<&'a str> {
        let mut lines = Vec::new();
        self.append_lines(recognised, &mut lines);
        lines
    }

    fn append_lines<'a>(&'a self, recognised: &[&str], lines: &mut Vec<&'a str>) {
        for item in &self.items {
            match item {
                Item::Statement(line, _) => lines.push(line.as_str()),
                Item::Block(block) => {
                    if recognised.contains(&block.name.as_str()) {
                        continue;
                    }
                    lines.push(block.header.as_str());
                    block.append_lines(recognised, lines);
                    lines.push(block.closing.as_str());
                }
            }
        }
    }

    /// Return direct named children in source order.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Retained for C13 projection retirement")
    )]
    pub fn blocks_any(&self) -> impl Iterator<Item = &Block> {
        self.items.iter().filter_map(|item| match item {
            Item::Block(block) => Some(block),
            Item::Statement(_, _) => None,
        })
    }

    #[expect(dead_code, reason = "Retained for C13 projection retirement")]
    pub fn blocks_matching<'a>(&'a self, recognised: &[&str]) -> Vec<&'a Block> {
        let mut blocks = Vec::new();
        self.append_matching(recognised, &mut blocks);
        blocks
    }

    #[expect(dead_code, reason = "Retained for C13 projection retirement")]
    fn append_matching<'a>(&'a self, recognised: &[&str], blocks: &mut Vec<&'a Block>) {
        for block in self.blocks_any() {
            if recognised.contains(&block.name.as_str()) {
                blocks.push(block);
            } else {
                block.append_matching(recognised, blocks);
            }
        }
    }
}

/// Legacy structure snapshots for the unmigrated scanner.
#[cfg(test)]
pub fn scan(
    input: &str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Result<Vec<Block>, ConfigError> {
    let lines = Line::all(input);
    let mut scanner = Scanner::default();
    let mut position = (0, 0);
    while position.0 < lines.len() {
        let next = scanner.process_line(&lines, position, diagnostics);
        position = next?;
    }

    if let Some(frame) = scanner.frames.last() {
        return Err(ConfigError::Parse(format!(
            "unclosed block `{}` opened at line {}",
            frame.name, frame.line
        )));
    }
    Ok(scanner.roots)
}

/// Keep unmigrated sections on their bounded old adapter until their owning commit.
pub(super) fn scan_readers(
    input: &str,
    diagnostics: &mut ParserDiagnostics<'_>,
    saw_include: &mut bool,
) -> Result<Vec<Block>, ConfigError> {
    let reference = diagnostics.source();
    let shared: Arc<str> = Arc::from(input);
    let source = Source::shared(shared, reference.clone());
    let mut lexical = Vec::new();
    let tokens = source.tokenize(&mut lexical);
    let lines = Line::all(input);
    let mut scanner = Scanner::default();
    let mut position = (0, 0);
    let mut migrated_root_seen = false;
    while position.0 < lines.len() {
        let offset = lines[position.0].start + position.1;
        let start = tokens.partition_point(|token| token.span.start < offset);
        let first = (start..tokens.len()).find(|&index| !tokens[index].kind.is_trivia());
        let migrated = scanner.at_root()
            && first.is_some_and(|index| {
                let name = source.raw(tokens[index].span);
                let named = matches!(
                    name,
                    "global"
                        | "experimental"
                        | "node"
                        | "subscription"
                        | "group"
                        | "routing"
                        | "dns"
                        | "include"
                );
                let glued = name.strip_suffix('{').is_some_and(|name| {
                    matches!(
                        name,
                        "global"
                            | "experimental"
                            | "node"
                            | "subscription"
                            | "group"
                            | "routing"
                            | "dns"
                            | "include"
                    )
                });
                let opener = tokens[index + 1..]
                    .iter()
                    .find(|token| !token.kind.is_trivia());
                // Frozen empty-root spelling stays on the old structural adapter until C13.
                let empty = opener.is_some_and(|token| {
                    token.line == tokens[index].line
                        && token.kind == TokenKind::Word
                        && source.raw(token.span) == "{}"
                });
                tokens[index].line == position.0 + 1
                    && (glued || (named && (!empty || name == "include")))
            });
        if migrated {
            migrated_root_seen = true;
            let start = first.unwrap();
            let byte_start = tokens[start].span.start;
            let include = source.raw(tokens[start].span) == "include";
            if include {
                let opener =
                    (start + 1..tokens.len()).find(|&index| !tokens[index].kind.is_trivia());
                *saw_include |= opener.is_some_and(|index| {
                    tokens[index].kind == TokenKind::OpenBrace
                        || source.raw(tokens[index].span) == "{}"
                });
                // Compact empty roots keep their frozen spelling until C13.
                if let Some(index) = opener.filter(|&index| source.raw(tokens[index].span) == "{}")
                {
                    let byte_end = tokens[index].span.end;
                    if tokens[index].line != tokens[start].line {
                        diagnostics.output.push(source.diagnostic(
                            tokens[index].span,
                            crate::diagnostic::Severity::Warning,
                            "legacy-include-opener",
                            "put the include opener on its header line",
                        ));
                    }
                    scanner.roots.push(Block {
                        name: "include".to_owned(),
                        items: Vec::new(),
                        line: tokens[start].line,
                        header: "include".to_owned(),
                        closing: String::new(),
                        segments: Vec::new(),
                    });
                    let line = line_for_offset(&lines, byte_end);
                    position = (line, byte_end - lines[line].start);
                    continue;
                }
            }
            let mut opened = false;
            let mut depth = 0usize;
            let mut end = tokens.len();
            for (index, token) in tokens.iter().enumerate().skip(start) {
                match token.kind {
                    TokenKind::OpenBrace => {
                        depth += 1;
                        opened = true;
                    }
                    TokenKind::CloseBrace if opened => {
                        depth -= 1;
                        if depth == 0 {
                            end = index + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let byte_end = tokens[end - 1].span.end;
            let dns_root = source.raw(tokens[start].span) == "dns";
            for token in &tokens[start..end] {
                if !include
                    && token.kind == TokenKind::Comment
                    && source.raw(token.span).contains(['{', '}'])
                    && (!dns_root
                        || source.text()[..token.span.start]
                            .rsplit('\n')
                            .next()
                            .is_some_and(|prefix| !prefix.trim().is_empty()))
                {
                    diagnostics.output.push(source.diagnostic(
                        token.span,
                        crate::diagnostic::Severity::Warning,
                        "legacy-comment-brace",
                        "comments do not close blocks; put the closer outside the comment",
                    ));
                }
            }
            let selected_errors = lexical
                .iter()
                .filter(|diagnostic| {
                    diagnostic
                        .span
                        .as_ref()
                        .is_some_and(|span| byte_start <= span.start && span.start < byte_end)
                })
                .cloned()
                .collect();
            let document = Arc::new(
                Document::from_tokens(
                    source.clone(),
                    tokens[start..end].to_vec(),
                    selected_errors,
                    diagnostics.output,
                )
                .map_err(|error| {
                    if let Some(index) = diagnostics.output.iter().rposition(|diagnostic| {
                        diagnostic.terminal && diagnostic.span == error.error.diagnostic.span
                    }) {
                        diagnostics.output.remove(index);
                    }
                    diagnostics.failure = Some((*error.error.diagnostic).clone());
                    error.error.into_legacy()
                })?,
            );
            for segment in document.sections() {
                if segment.header() == "include" {
                    let mut body = segment.body().expect("include block");
                    while body.next() {
                        let token = body.token().unwrap();
                        let text = super::read::Text {
                            source: segment.source(),
                            tokens: std::slice::from_ref(token),
                            span: token.span,
                        };
                        if let Some(offset) = text.find("#") {
                            text.sub(offset, offset + 1).notice(
                                diagnostics,
                                crate::diagnostic::Severity::Warning,
                                "legacy-include-hash",
                                "glued `#` is data; separate include comments with whitespace",
                            );
                        }
                    }
                }
                scanner.roots.push(Block {
                    name: segment.header().to_owned(),
                    items: Vec::new(),
                    line: source.location(segment.span().start).0,
                    header: segment.header().to_owned(),
                    closing: String::new(),
                    segments: vec![OwnedSegment {
                        document: document.clone(),
                        range: segment.range(),
                    }],
                });
            }
            let line = line_for_offset(&lines, byte_end);
            position = (line, byte_end - lines[line].start);
            if position.1 >= lines[line].text.len() {
                position = (line + 1, 0);
            }
            continue;
        }
        if migrated_root_seen
            && scanner.at_root()
            && let Some(index) = first.filter(|&index| tokens[index].line == position.0 + 1)
        {
            let token = &tokens[index];
            if token.kind == TokenKind::CloseBrace {
                diagnostics.output.push(source.diagnostic(
                    token.span,
                    crate::diagnostic::Severity::Warning,
                    "unmatched-close",
                    "unmatched closing brace was ignored",
                ));
                position.1 = token.span.end - lines[position.0].start;
                continue;
            }
            let end = tokens[index..]
                .iter()
                .position(|token| token.line != position.0 + 1 || token.kind == TokenKind::Comment)
                .map_or(tokens.len(), |end| index + end);
            if source.raw(token.span) != "include"
                && !tokens[index..end].iter().any(|token| {
                    matches!(token.kind, TokenKind::OpenBrace | TokenKind::CloseBrace)
                        || source.raw(token.span).contains(['{', '}'])
                })
            {
                diagnostics.output.push(source.diagnostic(
                    Span {
                        end: tokens[end - 1].span.end,
                        ..token.span
                    },
                    crate::diagnostic::Severity::Warning,
                    "unknown-statement",
                    "statement outside a section was ignored",
                ));
                position = (position.0 + 1, 0);
                continue;
            }
        }
        let mut legacy = Vec::new();
        let next = scanner.process_line(&lines, position, &mut legacy);
        diagnostics.extend(legacy);
        position = next?;
    }
    if let Some(frame) = scanner.frames.last() {
        return Err(ConfigError::Parse(format!(
            "unclosed block `{}` opened at line {}",
            frame.name, frame.line
        )));
    }
    Ok(scanner.roots)
}

#[derive(Debug)]
struct Line<'a> {
    text: &'a str,
    start: usize,
    number: usize,
}

impl<'a> Line<'a> {
    fn all(input: &'a str) -> Vec<Self> {
        input
            .lines()
            .enumerate()
            .map(|(index, text)| Self {
                text,
                start: text.as_ptr() as usize - input.as_ptr() as usize,
                number: index + 1,
            })
            .collect()
    }
}

#[derive(Debug, Default)]
struct Scanner {
    roots: Vec<Block>,
    frames: Vec<Block>,
    braces: Vec<Brace>,
}

#[derive(Debug)]
enum Brace {
    Named,
    Anonymous,
}

impl Scanner {
    fn process_line(
        &mut self,
        lines: &[Line<'_>],
        (index, cursor): (usize, usize),
        diagnostics: &mut Vec<ConfigDiagnostic>,
    ) -> Result<(usize, usize), ConfigError> {
        let line_text = lines[index].text;
        let line_number = lines[index].number;

        Ok(
            match self.process_normal_line(line_text, line_number, cursor, diagnostics)? {
                Some(cursor) => (index, cursor),
                None => (index + 1, 0),
            },
        )
    }

    fn process_normal_line(
        &mut self,
        text: &str,
        line: usize,
        start: usize,
        diagnostics: &mut Vec<ConfigDiagnostic>,
    ) -> Result<Option<usize>, ConfigError> {
        let remainder = &text[start..];
        let trimmed = remainder.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }

        let bytes = text.as_bytes();
        let mut index = start;
        let mut segment_start = start;
        let mut after_boundary = false;

        while index < bytes.len() {
            if after_boundary
                && bytes[index] == b'#'
                && text[segment_start..index].trim().is_empty()
            {
                return Ok(None);
            }
            match bytes[index] {
                b'\'' | b'"' => {
                    if let Some(end) = quoted_end(bytes, index) {
                        index = end;
                    } else {
                        // An unmatched quote is ordinary text.  In
                        // particular, braces after it remain structural.
                        index += 1;
                    }
                    continue;
                }
                b'{' => {
                    let in_subscription =
                        self.frames.iter().any(|block| block.name == "subscription");
                    if let Some(name) = named_opener(text, segment_start, index, in_subscription) {
                        self.frames.push(Block {
                            name: name.to_string(),
                            items: Vec::new(),
                            line,
                            header: text[segment_start..=index].trim().to_string(),
                            closing: String::new(),
                            segments: Vec::new(),
                        });
                        self.braces.push(Brace::Named);
                        segment_start = index + 1;
                        after_boundary = true;
                    } else {
                        if self.frames.is_empty() && self.braces.is_empty() {
                            return Err(ConfigError::Parse(format!(
                                "unexpected `{{` at line {line}"
                            )));
                        }
                        self.braces.push(Brace::Anonymous);
                    }
                    index += 1;
                }
                b'}' => {
                    let brace = self.braces.last();
                    match brace {
                        Some(Brace::Anonymous) => {
                            self.braces.pop();
                            index += 1;
                        }
                        Some(Brace::Named) => {
                            self.push_statement(text, segment_start, index, line, after_boundary);
                            self.braces.pop();
                            let mut frame =
                                self.frames.pop().expect("named brace always has a frame");
                            frame.closing = if text[index + 1..].trim_start().starts_with('#') {
                                text[index..].trim().to_string()
                            } else {
                                "}".to_string()
                            };
                            if let Some(parent) = self.frames.last_mut() {
                                parent.items.push(Item::Block(frame));
                            } else {
                                self.roots.push(frame);
                                return Ok(Some(index + 1));
                            }
                            segment_start = index + 1;
                            after_boundary = true;
                            index += 1;
                        }
                        None => {
                            diagnostics.push(ConfigDiagnostic {
                                setting: String::new(),
                                value: line.to_string(),
                                message: "unmatched `}` ignored".to_string(),
                            });
                            return Ok(None);
                        }
                    }
                }
                _ => index += 1,
            }
        }

        self.push_statement(text, segment_start, bytes.len(), line, after_boundary);
        Ok(None)
    }

    fn push_statement(
        &mut self,
        text: &str,
        start: usize,
        end: usize,
        line: usize,
        after_boundary: bool,
    ) {
        let statement = text[start..end].trim();
        if statement.is_empty() || (after_boundary && statement.starts_with('#')) {
            return;
        }
        if let Some(frame) = self.frames.last_mut() {
            frame
                .items
                .push(Item::Statement(statement.to_string(), line));
        }
    }

    fn at_root(&self) -> bool {
        self.frames.is_empty() && self.braces.is_empty()
    }
}

fn named_opener(
    text: &str,
    segment_start: usize,
    brace: usize,
    in_subscription: bool,
) -> Option<&str> {
    let prefix = text[segment_start..brace].trim();
    if prefix.is_empty() {
        return None;
    }
    let rest_is_blank = text[brace + 1..].trim().is_empty();
    if rest_is_blank
        || (in_subscription
            && prefix
                .split_once(':')
                .is_some_and(|(_, value)| value.trim().is_empty()))
    {
        return Some(prefix);
    }

    if !text[..brace]
        .chars()
        .next_back()
        .is_some_and(char::is_whitespace)
    {
        return None;
    }
    if prefix.chars().any(char::is_whitespace) {
        return None;
    }
    if prefix
        .chars()
        .any(|character| matches!(character, '\'' | '"' | '(' | ')' | '{' | '}'))
    {
        return None;
    }
    Some(prefix)
}

fn line_for_offset(lines: &[Line<'_>], offset: usize) -> usize {
    let mut low = 0usize;
    let mut high = lines.len();
    while low + 1 < high {
        let middle = (low + high) / 2;
        if lines[middle].start <= offset {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

#[cfg(test)]
mod tests;
