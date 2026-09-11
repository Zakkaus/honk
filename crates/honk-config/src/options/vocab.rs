//! Shared semantic conversion helpers used by config adapters.

/// Resolve optional text claims without trimming nonempty values.
///
/// Claims containing only whitespace are absent. Remaining claims must carry
/// identical bytes; otherwise the semantic alias group conflicts.
pub fn optional_text<'a, I>(values: I) -> Result<Option<&'a str>, &'static str>
where
    I: IntoIterator<Item = Option<&'a str>>,
{
    let mut resolved = None;
    for value in values.into_iter().flatten() {
        if value.trim().is_empty() {
            continue;
        }
        if let Some(previous) = resolved {
            if previous != value {
                return Err("conflicting optional text claims");
            }
        } else {
            resolved = Some(value);
        }
    }
    Ok(resolved)
}

/// Normalize the optional VLESS flow value.
///
/// Empty and whitespace-only values are absent. The only supported nonempty
/// value is the exact Vision flow spelling.
pub fn optional_flow(value: Option<&str>) -> Result<Option<&str>, &'static str> {
    let Some(value) = optional_text([value])? else {
        return Ok(None);
    };
    if value == "xtls-rprx-vision" {
        Ok(Some(value))
    } else {
        Err("unsupported VLESS flow")
    }
}
