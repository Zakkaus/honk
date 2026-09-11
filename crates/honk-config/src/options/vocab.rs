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

/// Normalize a stream transport claim while retaining the caller's source
/// spelling for storage. Empty and TCP both mean raw TCP.
pub fn stream_transport(value: &str) -> Result<&'static str, &'static str> {
    match value {
        "" | "tcp" => Ok("tcp"),
        "ws" => Ok("ws"),
        "grpc" => Ok("grpc"),
        _ => Err("unsupported stream transport"),
    }
}

/// Decode share-link certificate-verification text into the skip-verification
/// boolean used by the canonical TLS options.
pub fn verification_text(value: &str) -> Result<bool, &'static str> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value == "1"
        || value.eq_ignore_ascii_case("on")
    {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("f")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("n")
        || value == "0"
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("t")
        || value.eq_ignore_ascii_case("y")
    {
        return Ok(false);
    }
    Err("invalid certificate verification boolean")
}
