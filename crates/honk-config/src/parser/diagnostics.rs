use std::collections::HashMap;

use super::read::Text;
use super::structure::{Block, Item};
use crate::diagnostic::{
    ConfigDiagnostic, DetailedDiagnostic, SafeValue, SettingPath, SourceRef, project_legacy,
};
use crate::error::DetailedConfigError;

#[derive(Clone)]
struct Location {
    source: SourceRef,
    line: Option<usize>,
    span: Option<std::ops::Range<usize>>,
    byte_column: Option<usize>,
}

#[derive(Clone)]
struct GroupLocation {
    location: Location,
    filters: Vec<Location>,
}

/// Transient old-reader coordinates; no input text survives in returned diagnostics.
pub(super) struct ParserDiagnostics<'a> {
    pub output: &'a mut Vec<DetailedDiagnostic>,
    current: Location,
    statements: HashMap<usize, Location>,
    fields: HashMap<String, Location>,
    groups: Vec<GroupLocation>,
    group: Option<usize>,
    subscription: Option<usize>,
    entry: Option<usize>,
    pub failure: Option<DetailedDiagnostic>,
    root: &'static str,
    attempt_start: usize,
}

impl<'a> ParserDiagnostics<'a> {
    pub fn new(output: &'a mut Vec<DetailedDiagnostic>, source: SourceRef) -> Self {
        Self {
            attempt_start: output.len(),
            root: "config",
            output,
            current: Location {
                source,
                line: None,
                span: None,
                byte_column: None,
            },
            statements: HashMap::new(),
            fields: HashMap::new(),
            groups: Vec::new(),
            group: None,
            subscription: None,
            entry: None,
            failure: None,
        }
    }

    pub fn source(&self) -> SourceRef {
        self.current.source.clone()
    }

    pub fn field_location(&self, field: &str) -> (SourceRef, Option<usize>) {
        let location = self.fields.get(field).unwrap_or(&self.current);
        (location.source.clone(), location.line)
    }

    pub fn parse_share_link(
        &mut self,
        link: &str,
    ) -> Result<crate::node::Node, crate::error::DetailedConfigError> {
        let source = self.source();
        let location = &self.current;
        let entry = self.entry;
        // Node tags are not schema fields: every link diagnostic belongs to this entry.
        let locate_entry = |diagnostic: &mut DetailedDiagnostic| {
            diagnostic.source = source.clone();
            diagnostic.line = location.line;
            diagnostic.span = location.span.clone();
            diagnostic.byte_column = location.byte_column;
            diagnostic.entry_index = entry;
            if let Some(crate::diagnostic::SettingSegment::Field(root)) =
                diagnostic.setting.0.first_mut()
                && *root == "config"
            {
                *root = "nodes";
            }
            if let Some(index) = entry {
                diagnostic
                    .setting
                    .0
                    .insert(1, crate::diagnostic::SettingSegment::Index(index));
            }
        };
        crate::node::Node::parse_share_link(link, &source, &mut |mut diagnostic| {
            locate_entry(&mut diagnostic);
            self.output.push(diagnostic);
        })
        .map_err(|mut error| {
            locate_entry(error.diagnostic.as_mut());
            error
        })
    }

    pub fn set_source(&mut self, source: SourceRef) {
        self.current = Location {
            source,
            line: None,
            span: None,
            byte_column: None,
        };
        self.fields.clear();
    }

    pub fn register_blocks(&mut self, blocks: &[Block], source: &SourceRef) {
        for block in blocks {
            self.register_block(block, source);
        }
    }

    fn register_block(&mut self, block: &Block, source: &SourceRef) {
        self.statements.insert(
            block.header.as_ptr() as usize,
            Location {
                source: source.clone(),
                line: Some(block.line),
                span: None,
                byte_column: None,
            },
        );
        self.statements.insert(
            block.closing.as_ptr() as usize,
            Location {
                source: source.clone(),
                line: None,
                span: None,
                byte_column: None,
            },
        );
        for item in &block.items {
            match item {
                Item::Statement(text, line) => {
                    self.statements.insert(
                        text.as_ptr() as usize,
                        Location {
                            source: source.clone(),
                            line: Some(*line),
                            span: None,
                            byte_column: None,
                        },
                    );
                }
                Item::Block(child) => self.register_block(child, source),
            }
        }
    }

    fn location(&self, line: &str) -> Location {
        self.statements
            .get(&(line.as_ptr() as usize))
            .cloned()
            .unwrap_or_else(|| self.current.clone())
    }

    pub fn at_line(&mut self, line: &str) {
        self.current = self.location(line);
    }

    fn text_location(text: Text<'_, '_>) -> Location {
        let (line, column) = text.source.location(text.span.start);
        Location {
            source: text.source.reference(),
            line: Some(line),
            span: Some(text.span.start..text.span.end),
            byte_column: Some(column),
        }
    }

    pub fn at_text(&mut self, text: Text<'_, '_>) {
        self.current = Self::text_location(text);
    }

    pub fn register_field(&mut self, key: &str, text: Text<'_, '_>) {
        self.fields
            .insert(key.to_owned(), Self::text_location(text));
    }

    pub fn entry_text(&mut self, text: Text<'_, '_>, index: usize) {
        self.at_text(text);
        self.entry = Some(index);
    }

    pub fn begin_group_text(&mut self, text: Text<'_, '_>, index: usize) {
        self.at_text(text);
        self.fields.clear();
        self.entry = None;
        self.subscription = None;
        self.group = Some(index);
        self.groups.push(GroupLocation {
            location: self.current.clone(),
            filters: Vec::new(),
        });
    }

    pub fn remember_filter_text(&mut self, text: Text<'_, '_>) {
        self.groups
            .last_mut()
            .expect("group context")
            .filters
            .push(Self::text_location(text));
    }

    pub fn subscription_text(&mut self, text: Text<'_, '_>, index: usize) {
        self.at_text(text);
        self.fields.clear();
        self.entry = None;
        self.group = None;
        self.subscription = Some(index);
    }
    pub fn at_section(&mut self, section: &Block, excluded: &[&str]) {
        self.at_line(&section.header);
        self.root = match section.name.as_str() {
            "node" => "nodes",
            "subscription" => "subscriptions",
            "group" => "groups",
            _ => "config",
        };
        self.group = None;
        self.subscription = None;
        self.entry = None;
        self.fields.clear();
        for line in section.lines_except(excluded) {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, _)) = trimmed.split_once(':') {
                self.fields
                    .insert(key.trim().to_owned(), self.location(line));
            }
        }
    }

    pub fn select_group(&mut self, index: usize) {
        self.group = Some(index);
        self.subscription = None;
        self.entry = None;
        self.fields.clear();
        if let Some(group) = self.groups.get(index - 1) {
            self.current = group.location.clone();
        }
    }

    pub fn entry(&mut self, line: &str, index: usize) {
        self.at_line(line);
        self.entry = Some(index);
    }

    pub fn push(&mut self, legacy: ConfigDiagnostic) {
        let ttl = legacy.setting.starts_with("dns.fixed_domain_ttl.");
        let mut location = legacy
            .setting
            .rsplit('.')
            .next()
            .and_then(|key| self.fields.get(key))
            .cloned()
            .unwrap_or_else(|| self.current.clone());
        if ttl {
            location = self.current.clone();
        }
        let mut diagnostic = project_legacy(legacy, location.source.clone());
        if let Some(index) = self.group {
            if let Some(crate::diagnostic::SettingSegment::Field(field)) =
                diagnostic.setting.0.last().cloned()
            {
                diagnostic.setting = SettingPath::new("groups").index(index).field(field);
                if field == "filter"
                    && let SafeValue::Ordinal(ordinal) = diagnostic.value
                {
                    if let Some(filter) = self
                        .groups
                        .get(index - 1)
                        .and_then(|group| group.filters.get(ordinal - 1))
                    {
                        location = filter.clone();
                    }
                    diagnostic.entry_index = Some(ordinal);
                }
            }
        } else if let Some(index) = self.subscription {
            diagnostic.setting = SettingPath::new("subscriptions")
                .index(index)
                .field("interval");
            diagnostic.entry_index = Some(index);
        } else if ttl && let Some(index) = self.entry {
            diagnostic.setting = SettingPath::new("dns")
                .field("fixed_domain_ttl")
                .index(index);
            diagnostic.entry_index = Some(index);
        }
        diagnostic.source = location.source;
        if diagnostic.line.is_none() {
            diagnostic.line = location.line;
        }
        diagnostic.span = location.span;
        diagnostic.byte_column = location.byte_column;
        self.output.push(diagnostic);
    }

    pub fn extend(&mut self, diagnostics: impl IntoIterator<Item = ConfigDiagnostic>) {
        for diagnostic in diagnostics {
            self.push(diagnostic);
        }
    }

    pub fn notice(&mut self, mut diagnostic: DetailedDiagnostic) {
        diagnostic.setting = SettingPath::new(self.root);
        if let Some(group) = self.group {
            diagnostic.setting = SettingPath::new("groups").index(group).field("filter");
            if diagnostic.code == "empty-subgroup" {
                let ordinal = self.groups[group - 1].filters.len();
                diagnostic.setting = diagnostic.setting.index(ordinal);
                diagnostic.value = SafeValue::Ordinal(ordinal);
            }
        } else if let Some(entry) = self.entry {
            diagnostic.setting = diagnostic.setting.index(entry);
            diagnostic.entry_index = Some(entry);
        } else if let Some(subscription) = self.subscription {
            diagnostic.setting = diagnostic.setting.index(subscription);
        }
        let position = diagnostic
            .span
            .as_ref()
            .and_then(|span| {
                self.output[self.attempt_start..]
                    .iter()
                    .position(|existing| {
                        existing.source == diagnostic.source
                            && existing
                                .span
                                .as_ref()
                                .is_some_and(|existing| existing.start > span.start)
                    })
            })
            .map_or(self.output.len(), |index| self.attempt_start + index);
        self.output.insert(position, diagnostic);
    }

    pub fn emit(&mut self, mut diagnostic: DetailedDiagnostic) {
        let field = diagnostic
            .setting
            .0
            .last()
            .and_then(|segment| match segment {
                crate::diagnostic::SettingSegment::Field(field) => Some(*field),
                _ => None,
            });
        let location = field
            .and_then(|field| self.fields.get(field))
            .unwrap_or(&self.current);
        if diagnostic.span.is_none() {
            diagnostic.source = location.source.clone();
            diagnostic.line = location.line;
            diagnostic.span = location.span.clone();
            diagnostic.byte_column = location.byte_column;
        }
        diagnostic.entry_index = self.entry;
        self.output.push(diagnostic);
    }

    pub fn error(&self, error: crate::ConfigError) -> DetailedConfigError {
        let mut error = DetailedConfigError::from_legacy(error, self.source());
        if let Some(terminal) = &self.failure {
            error.diagnostic = Box::new(terminal.clone());
            return error;
        }
        let field = error
            .diagnostic
            .setting
            .0
            .iter()
            .rev()
            .find_map(|segment| match segment {
                crate::diagnostic::SettingSegment::Field(field) => Some(*field),
                _ => None,
            });
        let location = field
            .and_then(|field| self.fields.get(field))
            .unwrap_or(&self.current);
        error.diagnostic.source = location.source.clone();
        error.diagnostic.line = location.line;
        error.diagnostic.span = location.span.clone();
        error.diagnostic.byte_column = location.byte_column;
        if error.diagnostic.code == "unknown-traffic-predicate"
            && let Some(index) = self.entry
        {
            error.diagnostic.setting = error.diagnostic.setting.clone().index(index);
            error.diagnostic.entry_index = Some(index);
        }
        error
    }
}
