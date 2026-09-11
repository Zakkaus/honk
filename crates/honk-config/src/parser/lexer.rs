//! Lossless physical-line tokens. Semantic punctuation belongs to section readers.

use crate::diagnostic::{DetailedDiagnostic, SafeValue, SettingPath, Severity, SourceRef};

/// Half-open UTF-8 byte coordinates in the source's attempt-local table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub source: usize,
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// Interior of a matched quote span; escapes remain source bytes.
    pub fn interior(self) -> Self {
        assert!(self.end >= self.start + 2);
        Self {
            start: self.start + 1,
            end: self.end - 1,
            ..self
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Word,
    Whitespace,
    Newline,
    Comment,
    OpenBrace,
    CloseBrace,
    Error { opener: usize },
}

impl TokenKind {
    pub fn is_trivia(self) -> bool {
        matches!(self, Self::Whitespace | Self::Newline | Self::Comment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub span: Span,
    /// Matched spans including both quote delimiters, in source order.
    pub quoted: Vec<Span>,
    pub kind: TokenKind,
    pub line: usize,
}

/// Borrows input once; diagnostics retain only `reference` metadata.
#[derive(Debug)]
pub struct Source<'a> {
    text: &'a str,
    reference: SourceRef,
    line_starts: Vec<usize>,
}

impl<'a> Source<'a> {
    pub fn new(text: &'a str, reference: SourceRef) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            text.bytes()
                .enumerate()
                .filter_map(|(i, b)| (b == b'\n').then_some(i + 1)),
        );
        Self {
            text,
            reference,
            line_starts,
        }
    }

    pub fn text(&self) -> &'a str {
        self.text
    }

    pub fn span(&self, start: usize, end: usize) -> Span {
        Span {
            source: self.reference.index(),
            start,
            end,
        }
    }

    pub fn raw(&self, span: Span) -> &'a str {
        assert_eq!(span.source, self.reference.index());
        &self.text[span.start..span.end]
    }

    pub fn location(&self, offset: usize) -> (usize, usize) {
        assert!(offset <= self.text.len());
        let line = self.line_starts.partition_point(|&start| start <= offset);
        (line, offset - self.line_starts[line - 1] + 1)
    }

    pub fn diagnostic(
        &self,
        span: Span,
        severity: Severity,
        code: &'static str,
        message: &'static str,
    ) -> DetailedDiagnostic {
        let mut diagnostic = DetailedDiagnostic::warning(
            code,
            self.reference.clone(),
            SettingPath::new("config"),
            SafeValue::Redacted,
            message,
        );
        let (line, column) = self.location(span.start);
        diagnostic.span = Some(span.start..span.end);
        diagnostic.line = Some(line);
        diagnostic.byte_column = Some(column);
        diagnostic.severity = severity;
        diagnostic
    }

    /// Includes trivia, so concatenating raw token spans recovers the entire input.
    /// Quote errors append once and remain nonterminal until the reader decides recovery.
    pub fn tokenize(&self, diagnostics: &mut Vec<DetailedDiagnostic>) -> Vec<Token> {
        let bytes = self.text.as_bytes();
        let mut tokens = Vec::new();
        for (line_index, &start) in self.line_starts.iter().enumerate() {
            let next = self
                .line_starts
                .get(line_index + 1)
                .copied()
                .unwrap_or(bytes.len());
            let mut end = next;
            if end > start && bytes[end - 1] == b'\n' {
                end -= 1;
                if end > start && bytes[end - 1] == b'\r' {
                    end -= 1;
                }
            }
            let mut index = start;
            while index < end {
                let token_start = index;
                let mut quoted = Vec::new();
                let kind;
                if self.whitespace_width(index) != 0 {
                    while index < end && self.whitespace_width(index) != 0 {
                        index += self.whitespace_width(index);
                    }
                    kind = TokenKind::Whitespace;
                } else if bytes[index] == b'#' {
                    index = end;
                    kind = TokenKind::Comment;
                } else {
                    let mut error = None;
                    while index < end && self.whitespace_width(index) == 0 {
                        let boundary =
                            index == token_start || matches!(bytes[index - 1], b'(' | b',');
                        if boundary && matches!(bytes[index], b'\'' | b'"') {
                            if let Some(close) = quoted_end(&bytes[..end], index) {
                                quoted.push(self.span(index, close));
                                index = close;
                                continue;
                            }
                            error = Some(index);
                            diagnostics.push(self.diagnostic(
                                self.span(index, end),
                                Severity::Error,
                                "unterminated-quote",
                                "quote must close on the same physical line",
                            ));
                            index = end;
                            break;
                        }
                        index += self.text[index..].chars().next().unwrap().len_utf8();
                    }
                    kind = if let Some(opener) = error {
                        TokenKind::Error { opener }
                    } else if quoted.is_empty() && index == token_start + 1 {
                        match bytes[token_start] {
                            b'{' => TokenKind::OpenBrace,
                            b'}' => TokenKind::CloseBrace,
                            _ => TokenKind::Word,
                        }
                    } else {
                        TokenKind::Word
                    };
                }
                tokens.push(Token {
                    span: self.span(token_start, index),
                    quoted,
                    kind,
                    line: line_index + 1,
                });
            }
            if end < next {
                tokens.push(Token {
                    span: self.span(end, next),
                    quoted: Vec::new(),
                    kind: TokenKind::Newline,
                    line: line_index + 1,
                });
            }
        }
        tokens
    }

    fn whitespace_width(&self, index: usize) -> usize {
        let byte = self.text.as_bytes()[index];
        if byte.is_ascii() {
            usize::from(byte.is_ascii_whitespace())
        } else {
            let ch = self.text[index..].chars().next().unwrap();
            if ch.is_whitespace() { ch.len_utf8() } else { 0 }
        }
    }
}

/// Return the byte index immediately after the matching quote. A backslash
/// skips the next byte without decoding it.
pub(super) fn quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}
