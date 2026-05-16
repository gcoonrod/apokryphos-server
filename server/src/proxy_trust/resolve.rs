//! Pure proxy-trust resolution (R11, invariants P3..P7).
//!
//! `axum`-free so the algorithm can be unit-tested in isolation.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy)]
pub struct EffectiveAddress {
    pub addr: IpAddr,
    pub scheme: EffectiveScheme,
}

/// Resolve the effective client IP and scheme from the immediate peer and the
/// forwarded headers, consulting `trusted_proxies` to decide which to trust.
///
/// Fail-closed semantics (R11):
/// - Empty `trusted_proxies` → always direct peer (FR-009).
/// - Peer not in any trusted CIDR → direct peer (FR-008).
/// - Trusted peer, multi-hop XFF → leftmost entry (FR-010).
/// - Trusted peer, malformed XFF → direct peer (fail closed).
/// - Trusted peer, unknown/missing XFP → direct peer's scheme (fail closed).
pub fn resolve_effective_address(
    peer_addr: IpAddr,
    peer_scheme: EffectiveScheme,
    trusted_proxies: &[ipnet::IpNet],
    x_forwarded_for: Option<&str>,
    x_forwarded_proto: Option<&str>,
) -> EffectiveAddress {
    if trusted_proxies.is_empty() {
        return EffectiveAddress {
            addr: peer_addr,
            scheme: peer_scheme,
        };
    }

    let peer_trusted = trusted_proxies.iter().any(|net| net.contains(&peer_addr));
    if !peer_trusted {
        return EffectiveAddress {
            addr: peer_addr,
            scheme: peer_scheme,
        };
    }

    let addr = match x_forwarded_for {
        Some(s) => s
            .split(',')
            .next()
            .map(str::trim)
            .and_then(|s| s.parse::<IpAddr>().ok())
            .unwrap_or(peer_addr),
        None => peer_addr,
    };

    let scheme = match x_forwarded_proto {
        Some(s) if s.eq_ignore_ascii_case("https") => EffectiveScheme::Https,
        Some(s) if s.eq_ignore_ascii_case("http") => EffectiveScheme::Http,
        _ => peer_scheme,
    };

    EffectiveAddress { addr, scheme }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn cidr(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn empty_trusted_list_always_returns_peer() {
        let r = resolve_effective_address(
            ipv4(127, 0, 0, 1),
            EffectiveScheme::Http,
            &[],
            Some("1.2.3.4"),
            Some("https"),
        );
        assert_eq!(r.addr, ipv4(127, 0, 0, 1));
        assert_eq!(r.scheme, EffectiveScheme::Http);
    }

    #[test]
    fn untrusted_peer_returns_peer_values() {
        let r = resolve_effective_address(
            ipv4(8, 8, 8, 8),
            EffectiveScheme::Http,
            &[cidr("10.0.0.0/8")],
            Some("1.2.3.4"),
            Some("https"),
        );
        assert_eq!(r.addr, ipv4(8, 8, 8, 8));
        assert_eq!(r.scheme, EffectiveScheme::Http);
    }

    #[test]
    fn trusted_peer_honors_single_xff() {
        let r = resolve_effective_address(
            ipv4(10, 0, 0, 5),
            EffectiveScheme::Http,
            &[cidr("10.0.0.0/8")],
            Some("1.2.3.4"),
            Some("https"),
        );
        assert_eq!(r.addr, ipv4(1, 2, 3, 4));
        assert_eq!(r.scheme, EffectiveScheme::Https);
    }

    #[test]
    fn trusted_peer_takes_leftmost_xff() {
        let r = resolve_effective_address(
            ipv4(10, 0, 0, 5),
            EffectiveScheme::Http,
            &[cidr("10.0.0.0/8")],
            Some("1.2.3.4, 10.0.0.5"),
            None,
        );
        assert_eq!(r.addr, ipv4(1, 2, 3, 4));
    }

    #[test]
    fn single_ip_cidr_slash_32() {
        let r = resolve_effective_address(
            ipv4(10, 0, 0, 5),
            EffectiveScheme::Http,
            &[cidr("10.0.0.5/32")],
            Some("1.2.3.4"),
            None,
        );
        assert_eq!(r.addr, ipv4(1, 2, 3, 4));
    }

    #[test]
    fn large_cidr_slash_8() {
        let r = resolve_effective_address(
            ipv4(10, 1, 2, 3),
            EffectiveScheme::Http,
            &[cidr("10.0.0.0/8")],
            Some("1.2.3.4"),
            None,
        );
        assert_eq!(r.addr, ipv4(1, 2, 3, 4));
    }

    #[test]
    fn malformed_xff_falls_back_to_peer() {
        let r = resolve_effective_address(
            ipv4(10, 0, 0, 5),
            EffectiveScheme::Http,
            &[cidr("10.0.0.0/8")],
            Some("not-an-ip"),
            None,
        );
        assert_eq!(r.addr, ipv4(10, 0, 0, 5));
    }

    #[test]
    fn unknown_xfp_falls_back_to_peer_scheme() {
        let r = resolve_effective_address(
            ipv4(10, 0, 0, 5),
            EffectiveScheme::Https,
            &[cidr("10.0.0.0/8")],
            None,
            Some("gopher"),
        );
        assert_eq!(r.scheme, EffectiveScheme::Https);
    }

    #[test]
    fn ipv6_cidr() {
        let peer: IpAddr = "2001:db8::5".parse().unwrap();
        let r = resolve_effective_address(
            peer,
            EffectiveScheme::Http,
            &[cidr("2001:db8::/32")],
            Some("1.2.3.4"),
            None,
        );
        assert_eq!(r.addr, ipv4(1, 2, 3, 4));
    }
}
