use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCheckTarget<'a> {
    Literal(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid check target")]
pub struct InvalidCheckTarget;

/// Decode a DNS target without resolving names. Omitted ports are always 53.
pub fn decode_dns_check_target(value: &str) -> Result<DnsCheckTarget<'_>, InvalidCheckTarget> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return (address.port() != 0)
            .then_some(DnsCheckTarget::Literal(address))
            .ok_or(InvalidCheckTarget);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(DnsCheckTarget::Literal(SocketAddr::new(ip, 53)));
    }
    if let Some(body) = value.strip_prefix('[') {
        let (host, suffix) = body.split_once(']').ok_or(InvalidCheckTarget)?;
        let ip = host.parse::<Ipv6Addr>().map_err(|_| InvalidCheckTarget)?;
        let port = if suffix.is_empty() {
            53
        } else {
            dns_port(suffix.strip_prefix(':').ok_or(InvalidCheckTarget)?)?
        };
        return Ok(DnsCheckTarget::Literal(SocketAddr::new(ip.into(), port)));
    }
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, dns_port(port)?),
        None => (value, 53),
    };
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || "[]:/?#@\\".contains(c))
    {
        return Err(InvalidCheckTarget);
    }
    Ok(DnsCheckTarget::Domain { host, port })
}

fn dns_port(value: &str) -> Result<u16, InvalidCheckTarget> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InvalidCheckTarget);
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(InvalidCheckTarget)
}

/// Prefer the first literal, otherwise the first domain, without DNS I/O.
pub fn select_dns_check_target(
    values: &[String],
) -> Result<Option<DnsCheckTarget<'_>>, InvalidCheckTarget> {
    let mut first_domain = None;
    for value in values.iter().filter(|value| !value.trim().is_empty()) {
        match decode_dns_check_target(value)? {
            target @ DnsCheckTarget::Literal(_) => return Ok(Some(target)),
            target @ DnsCheckTarget::Domain { .. } => {
                first_domain.get_or_insert(target);
            }
        }
    }
    Ok(first_domain)
}

pub(crate) fn validate_dns_check_targets(values: &[String]) -> Result<(), crate::ConfigError> {
    for (index, value) in values.iter().enumerate() {
        if !value.trim().is_empty() && decode_dns_check_target(value).is_err() {
            return Err(crate::ConfigError::Validation(format!(
                "global.udp_check_dns[{}]: invalid DNS check target",
                index + 1
            )));
        }
    }
    Ok(())
}
