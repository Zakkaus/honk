//! Reader punctuation over lexical spans; quotes and comments remain lexer-owned.

use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::lexer::{Source, Span, Token, TokenKind};
use super::structure::Block;
use crate::diagnostic::Severity;

#[derive(Clone, Copy)]
pub(super) struct Text<'d, 'a> {
    pub source: &'d Source<'a>,
    pub tokens: &'d [Token],
    pub span: Span,
}

impl<'d, 'a> Text<'d, 'a> {
    pub fn segment(segment: &Segment<'d, 'a>) -> Self {
        Self {
            source: segment.source(),
            tokens: segment.tokens(),
            span: segment.header_span(),
        }
    }

    pub fn raw(self) -> &'d str {
        self.source.raw(self.span)
    }

    pub fn sub(self, start: usize, end: usize) -> Self {
        Self {
            span: self
                .source
                .span(self.span.start + start, self.span.start + end),
            ..self
        }
    }

    pub fn trim(self) -> Self {
        let raw = self.raw();
        let start = raw.len() - raw.trim_start().len();
        self.sub(start, start + raw.trim().len())
    }

    pub fn quoted_prefix(self) -> Option<Self> {
        let text = self.trim();
        self.tokens
            .iter()
            .flat_map(|token| &token.quoted)
            .find(|span| span.start == text.span.start && span.end <= text.span.end)
            .map(|&span| Self { span, ..self })
    }

    pub fn unquote(self) -> Self {
        let text = self.trim();
        if let Some(quoted) = text
            .quoted_prefix()
            .filter(|quoted| quoted.span == text.span)
        {
            Self {
                span: quoted.span.interior(),
                ..text
            }
        } else {
            text
        }
    }
    pub fn find(self, delimiter: &str) -> Option<usize> {
        self.raw().match_indices(delimiter).find_map(|(offset, _)| {
            let position = self.span.start + offset;
            (!self
                .tokens
                .iter()
                .flat_map(|token| &token.quoted)
                .any(|quote| {
                    self.span.start <= quote.start
                        && quote.end <= self.span.end
                        && quote.start <= position
                        && position < quote.end
                }))
            .then_some(offset)
        })
    }

    pub fn split(self, delimiter: &str) -> Vec<Self> {
        let mut remaining = self;
        let mut parts = Vec::new();
        while let Some(offset) = remaining.find(delimiter) {
            parts.push(remaining.sub(0, offset));
            remaining = remaining.sub(offset + delimiter.len(), remaining.raw().len());
        }
        parts.push(remaining);
        parts
    }

    /// Return the leading parenthesized body and its untouched trailing span.
    pub fn parenthesized(self) -> Option<(Self, Self)> {
        let raw = self.raw().as_bytes();
        if raw.first() != Some(&b'(') {
            return None;
        }
        let mut quotes = self
            .tokens
            .iter()
            .flat_map(|token| &token.quoted)
            .filter(|quote| self.span.start <= quote.start && quote.end <= self.span.end)
            .peekable();
        let mut depth = 0;
        let mut index = 0;
        while index < raw.len() {
            let absolute = self.span.start + index;
            while quotes.peek().is_some_and(|quote| quote.end <= absolute) {
                quotes.next();
            }
            if let Some(quote) = quotes.peek().filter(|quote| quote.start <= absolute) {
                index = quote.end - self.span.start;
                quotes.next();
                continue;
            }
            match raw[index] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((self.sub(1, index), self.sub(index + 1, raw.len())));
                    }
                }
                _ => {}
            }
            index += 1;
        }
        None
    }

    pub fn kv(self) -> Option<(Self, Self)> {
        let colon = self.find(":")?;
        Some((
            self.sub(0, colon).trim(),
            self.sub(colon + 1, self.raw().len()).trim(),
        ))
    }

    pub fn has_error(self) -> bool {
        self.tokens.iter().any(|token| {
            matches!(token.kind, TokenKind::Error { .. })
                && token.span.start < self.span.end
                && self.span.start < token.span.end
        })
    }

    /// K01: a `#` glued to data is data, not a comment. Warn once at the
    /// first such byte outside a quoted span so users who relied on the old
    /// truncation see where their value now continues.
    /// The `#` that starts a comment after this text on the same line, if any.
    /// Segments carry no trivia tokens, so the position is read from the source;
    /// it is only ever used to locate a diagnostic, never to reinterpret the line.
    pub fn trailing_comment(self) -> Option<Self> {
        let rest = self.source.text()[self.span.end..].split('\n').next()?;
        let gap = rest.len() - rest.trim_start().len();
        rest[gap..].starts_with('#').then(|| Self {
            span: self
                .source
                .span(self.span.end + gap, self.span.end + gap + 1),
            ..self
        })
    }

    pub fn warn_glued_hash(self, diagnostics: &mut ParserDiagnostics<'_>) {
        let raw = self.raw();
        for (offset, byte) in raw.bytes().enumerate() {
            if byte != b'#' {
                continue;
            }
            let absolute = self.span.start + offset;
            if self
                .tokens
                .iter()
                .flat_map(|token| &token.quoted)
                .any(|quote| quote.start <= absolute && absolute < quote.end)
            {
                continue;
            }
            if offset == 0 || raw.as_bytes()[offset - 1].is_ascii_whitespace() {
                continue;
            }
            self.sub(offset, offset + 1).notice(
                diagnostics,
                Severity::Warning,
                "legacy-glued-hash",
                "glued `#` is data; separate comments with whitespace",
            );
            break;
        }
    }

    pub fn notice(
        self,
        sink: &mut ParserDiagnostics<'_>,
        severity: Severity,
        code: &'static str,
        message: &'static str,
    ) {
        sink.notice(self.source.diagnostic(self.span, severity, code, message));
    }
}

/// Compact empty blocks are a frozen compatibility form, not brace tokens in values.
pub(super) fn block_header<'d, 'a>(segment: &Segment<'d, 'a>) -> Option<Text<'d, 'a>> {
    let header = Text::segment(segment).trim();
    if segment.body().is_some() {
        return Some(header);
    }
    let last = segment.tokens().last()?;
    (last.kind == TokenKind::Word
        && header.source.raw(last.span) == "{}"
        && last.span.start > header.span.start)
        .then(|| header.sub(0, last.span.start - header.span.start).trim())
}

pub(super) fn child_statements<'d, 'a>(segment: &Segment<'d, 'a>) -> Vec<Text<'d, 'a>> {
    fn append<'d, 'a>(segment: &Segment<'d, 'a>, output: &mut Vec<Text<'d, 'a>>) {
        if let Some(mut body) = segment.body() {
            while body.next() {
                let child = body.next_segment().expect("statement or block header");
                if child.body().is_some() {
                    let mut header = Text::segment(&child);
                    header.span.end = child
                        .tokens()
                        .iter()
                        .find(|token| token.kind == TokenKind::OpenBrace)
                        .unwrap()
                        .span
                        .end;
                    output.push(header);
                    append(&child, output);
                } else {
                    output.push(Text::segment(&child));
                }
            }
        }
    }
    let mut output = Vec::new();
    append(segment, &mut output);
    output
}

pub(super) fn statements(section: &Block) -> Vec<Text<'_, 'static>> {
    section
        .segments
        .iter()
        .flat_map(|owned| child_statements(&owned.get()))
        .collect()
}
