//! Source coordinates for a setting path, recovered after a successful load.
//!
//! Validation runs on the assembled [`crate::Config`], which no longer knows
//! where its values were written. A refusal is placed here by walking the
//! loaded sources with the parser's own entry numbering.

use super::cursor::{BodySyntax, Document, Segment};
use super::diagnostics::ParserDiagnostics;
use super::lexer::{Source, Span};
use super::read::{self, Text};
use super::sources::{LoadedConfig, SourceSnapshot};
use crate::diagnostic::{DetailedDiagnostic, SettingSegment};
use crate::error::DetailedConfigError;

/// Place `diagnostic` at the text its setting was written in, or at the
/// nearest enclosing setting that `sources` contain. A diagnostic that already
/// has a span, or whose setting no source writes, is left unchanged.
pub fn locate_setting(sources: &[SourceSnapshot], diagnostic: &mut DetailedDiagnostic) {
    if diagnostic.span.is_some() {
        return;
    }
    let mut notices = Vec::new();
    let Ok(documents) = sources
        .iter()
        .map(|source| {
            Document::parse_attempt(
                Source::new(&source.content, source.source.clone()),
                &mut notices,
                false,
            )
        })
        .collect::<Result<Vec<_>, _>>()
    else {
        return;
    };
    if let Some(span) = Locator::new(&documents).find(&diagnostic.setting.0) {
        place(&documents, span, diagnostic);
    }
}

impl LoadedConfig {
    /// [`locate_setting`] in these sources.
    pub fn locate(&self, diagnostic: &mut DetailedDiagnostic) {
        locate_setting(&self.sources, diagnostic);
    }

    /// [`crate::Config::validate_detailed`], with the refusal placed in these
    /// sources by [`Self::locate`].
    pub fn validate_detailed(&self) -> Result<(), DetailedConfigError> {
        self.config.validate_detailed().map_err(|mut error| {
            self.locate(&mut error.diagnostic);
            error
        })
    }
}

fn place(documents: &[Document<'_>], span: Span, diagnostic: &mut DetailedDiagnostic) {
    let Some(document) = documents
        .iter()
        .find(|document| document.source().reference().index() == span.source)
    else {
        return;
    };
    let (line, column) = document.source().location(span.start);
    diagnostic.source = document.source().reference();
    diagnostic.line = Some(line);
    diagnostic.span = Some(span.start..span.end);
    diagnostic.byte_column = Some(column);
}

struct Locator<'d, 'a> {
    documents: &'d [Document<'a>],
}

impl<'d, 'a> Locator<'d, 'a> {
    fn new(documents: &'d [Document<'a>]) -> Self {
        Self { documents }
    }

    fn roots(&self, header: &str) -> Vec<Segment<'d, 'a>> {
        self.documents
            .iter()
            .flat_map(Document::sections)
            .filter(|root| root.header() == header)
            .collect()
    }

    fn diagnostics<T>(&self, read: impl FnOnce(&mut ParserDiagnostics<'_>) -> T) -> T {
        let mut output = Vec::new();
        let source = self.documents[0].source().reference();
        read(&mut ParserDiagnostics::new(&mut output, source))
    }

    /// The deepest written ancestor of `path`, the path itself included.
    fn find(&self, path: &[SettingSegment]) -> Option<Span> {
        let Some(SettingSegment::Field(root)) = path.first() else {
            return None;
        };
        let rest = &path[1..];
        let header = match *root {
            "nodes" => "node",
            "groups" => "group",
            "subscriptions" => "subscription",
            "config" => return None,
            other => other,
        };
        let roots = self.roots(header);
        let section = roots.last().map(|root| Text::segment(root).span)?;
        let found = match (*root, rest) {
            ("nodes", [SettingSegment::Index(index), ..]) => self.node(&roots, *index),
            ("subscriptions", [SettingSegment::Index(index), ..]) => {
                self.subscription(&roots, *index)
            }
            ("groups", [SettingSegment::Index(index), rest @ ..]) => {
                self.group(&roots, *index, rest)
            }
            ("routing", rest) => self.routing(&roots, rest),
            (
                "dns",
                [
                    SettingSegment::Field("routing"),
                    SettingSegment::Field(list),
                    rest @ ..,
                ],
            ) if matches!(*list, "request" | "response") => {
                self.dns_routing(&roots, *list == "response", rest)
            }
            (_, rest) => descend(roots, BodySyntax::Statements, rest),
        };
        Some(found.unwrap_or(section))
    }

    fn node(&self, roots: &[Segment<'_, '_>], index: usize) -> Option<Span> {
        let mut spans = Vec::new();
        let _ = self.diagnostics(|diagnostics| {
            super::entries::parse_node_section_indexed(roots, diagnostics, |_, span| {
                spans.push(span)
            })
        });
        spans.get(index.checked_sub(1)?).copied()
    }

    fn subscription(&self, roots: &[Segment<'_, '_>], index: usize) -> Option<Span> {
        let mut spans = Vec::new();
        let assets = crate::assets::AssetsConfig::default();
        let _ = self.diagnostics(|diagnostics| {
            super::entries::parse_subscription_section_indexed(
                roots,
                &assets,
                diagnostics,
                |_, span| spans.push(span),
            )
        });
        spans.get(index.checked_sub(1)?).copied().flatten()
    }

    fn group(
        &self,
        roots: &[Segment<'d, 'a>],
        index: usize,
        rest: &[SettingSegment],
    ) -> Option<Span> {
        let group = roots
            .iter()
            .filter_map(|root| root.body_with(BodySyntax::Declarations))
            .flatten()
            .filter(|segment| read::block_header(segment).is_some())
            .nth(index.checked_sub(1)?)?;
        let header = read::block_header(&group)?.span;
        Some(descend(vec![group], BodySyntax::Statements, rest).unwrap_or(header))
    }

    fn routing(&self, roots: &[Segment<'_, '_>], rest: &[SettingSegment]) -> Option<Span> {
        let mut rules = Vec::new();
        let mut fallback = None;
        let _ = self.diagnostics(|diagnostics| {
            super::routing::parse_section_indexed(roots, diagnostics, |ordinal, statement| {
                match ordinal {
                    Some(_) => rules.push(statement.span),
                    None => fallback = Some(statement.span),
                }
            })
        });
        match rest {
            [
                SettingSegment::Field("rules"),
                SettingSegment::Index(index),
                ..,
            ] => rules.get(index.checked_sub(1)?).copied(),
            [SettingSegment::Field("fallback"), ..] => fallback,
            _ => None,
        }
    }

    fn dns_routing(
        &self,
        roots: &[Segment<'_, '_>],
        response: bool,
        rest: &[SettingSegment],
    ) -> Option<Span> {
        let mut rules = Vec::new();
        let mut fallback = None;
        self.diagnostics(|diagnostics| {
            super::dns::parse_routing_indexed(roots, diagnostics, |list, index, line| {
                if list == response {
                    match index {
                        Some(_) => rules.push(line.span),
                        None => fallback = Some(line.span),
                    }
                }
            })
        });
        match rest {
            [
                SettingSegment::Field("rules"),
                SettingSegment::Index(index),
                ..,
            ] => rules.get(index.checked_sub(1)?).copied(),
            [SettingSegment::Field("fallback"), ..] => fallback,
            _ => None,
        }
    }
}

/// Follow named fields and blocks down from `parents`; the last declaration
/// of a name wins, as it does when the parser reads the value.
fn descend(
    parents: Vec<Segment<'_, '_>>,
    syntax: BodySyntax,
    path: &[SettingSegment],
) -> Option<Span> {
    let Some(SettingSegment::Field(name)) = path.first() else {
        return None;
    };
    let mut blocks = Vec::new();
    let mut found = None;
    for segment in parents
        .iter()
        .filter_map(|parent| parent.body_with(syntax))
        .flatten()
    {
        if let Some(header) = read::block_header(&segment) {
            if header.raw() == *name {
                found = Some(header.span);
                blocks.push(segment);
            }
        } else if let Some((key, _)) = Text::segment(&segment).trim().kv()
            && key.trim().raw() == *name
        {
            found = Some(Text::segment(&segment).trim().span);
            blocks.clear();
        }
    }
    if blocks.is_empty() {
        return found;
    }
    descend(blocks, BodySyntax::Statements, &path[1..]).or(found)
}
