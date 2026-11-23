//! Environment proxy policy for pinned model fetches.

use anyhow::{Context, Result};
use std::net::IpAddr;

fn hostname(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, rest) = ipv6.split_once(']')?;
        let port = rest.strip_prefix(':').and_then(|port| port.parse().ok());
        return Some((host, port));
    }
    let port = authority.rsplit_once(':').and_then(|(host, port)| {
        if host.contains(':') {
            return None;
        }
        Some((host, Some(port.parse().ok()?)))
    });
    port.or(Some((authority, None)))
        .filter(|(host, _)| !host.is_empty())
}

fn bypass(host: &str, port: u16, list: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
    {
        return true;
    }
    list.split(',').map(str::trim).any(|entry| {
        if entry == "*" {
            return true;
        }
        let Some((name, wanted_port)) = hostname(entry) else {
            return false;
        };
        if wanted_port.is_some_and(|wanted| wanted != port) {
            return false;
        }
        let name = name
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if name.is_empty() {
            return false;
        }
        if let Ok(address) = host.parse::<IpAddr>() {
            if let Some((network, bits)) = name.split_once('/') {
                return match (address, network.parse::<IpAddr>(), bits.parse::<u32>()) {
                    (IpAddr::V4(host), Ok(IpAddr::V4(network)), Ok(bits @ 1..=32)) => {
                        u32::from(host) >> (32 - bits) == u32::from(network) >> (32 - bits)
                    }
                    (IpAddr::V6(host), Ok(IpAddr::V6(network)), Ok(bits @ 1..=128)) => {
                        u128::from(host) >> (128 - bits) == u128::from(network) >> (128 - bits)
                    }
                    (IpAddr::V4(_), Ok(IpAddr::V4(_)), Ok(0))
                    | (IpAddr::V6(_), Ok(IpAddr::V6(_)), Ok(0)) => true,
                    _ => false,
                };
            }
            return name
                .parse::<IpAddr>()
                .is_ok_and(|candidate| address == candidate);
        }
        host == name
            || host
                .strip_suffix(&name)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn environment_proxy(url: &str, setting: impl Fn(&str) -> Option<String>) -> Option<String> {
    let (scheme, remainder) = url.split_once("://")?;
    let authority = remainder
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?;
    let (host, port) = hostname(authority)?;
    let (default_port, keys) = match scheme {
        "https" => (
            443,
            ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"],
        ),
        "http" => (80, ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]),
        _ => return None,
    };
    let first = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| setting(key).filter(|value| !value.trim().is_empty()))
    };
    if bypass(
        host,
        port.unwrap_or(default_port),
        &first(&["no_proxy", "NO_PROXY"]).unwrap_or_default(),
    ) {
        return None;
    }
    first(&keys)
}

pub(super) fn configured_proxy(url: &str) -> Result<Option<ureq::Proxy>> {
    environment_proxy(url, |key| std::env::var(key).ok())
        .map(|value| {
            // Proxy configuration may include credentials. Never surface
            // the value (or a lower-layer parse diagnostic containing it).
            ureq::Proxy::new(value.trim())
                .ok()
                .context("invalid model download proxy setting")
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_proxy_uses_scheme_precedence_and_respects_bypass() {
        let settings = [
            ("HTTPS_PROXY", "secure"),
            ("HTTP_PROXY", "plain"),
            ("ALL_PROXY", "all"),
            (
                "NO_PROXY",
                "mirror.local,.internal.example:443,10.4.0.0/16,[::1]",
            ),
        ];
        let choose = |url| {
            environment_proxy(url, |key| {
                settings
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| (*value).to_owned())
            })
        };
        assert_eq!(
            choose("https://artifact.example/path").as_deref(),
            Some("secure")
        );
        assert_eq!(
            choose("http://artifact.example/path").as_deref(),
            Some("plain")
        );
        assert_eq!(choose("https://sub.internal.example/path"), None);
        assert_eq!(
            choose("https://sub.internal.example:444/path").as_deref(),
            Some("secure")
        );
        assert_eq!(
            choose("https://notmirror.local/path").as_deref(),
            Some("secure")
        );
        assert_eq!(choose("https://mirror.local/path"), None);
        assert_eq!(choose("https://10.4.1.4/path"), None);
        assert_eq!(choose("https://[::1]:8123/path"), None);
        assert_eq!(choose("https://127.2.1.4:8123/path"), None);
        assert_eq!(choose("http://localhost/path"), None);
    }
}
