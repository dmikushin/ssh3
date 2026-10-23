//! Host candidates (SPEC §7.3 step 1): addresses of the **sending socket's own network
//! namespace**, never addresses of container bridges or non-routable ranges.
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::manager::non_routable;

/// Interface name prefixes of container/VM bridges whose addresses are never reachable from a
/// peer elsewhere (consultant point 2: bridge-only candidates must not be offered).
const BRIDGE_PREFIXES: &[&str] = &["docker", "br-", "veth", "virbr", "cni", "flannel", "podman", "lxc", "vnet"];

/// Host candidates for a socket bound to `local`. A socket bound to a specific address offers
/// exactly that address; a wildcard socket offers the addresses of the namespace's interfaces.
pub fn host_candidates(local: SocketAddr) -> Vec<SocketAddr> {
    let ip = match local.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    if !ip.is_unspecified() {
        return if non_routable(ip) { Vec::new() } else { vec![SocketAddr::new(ip, local.port())] };
    }
    let want_v6 = local.is_ipv6();
    interface_addrs()
        .into_iter()
        .filter(|(name, ip)| {
            !ip.is_loopback()
                && !non_routable(*ip)
                && !BRIDGE_PREFIXES.iter().any(|p| name.starts_with(p))
                && (want_v6 || ip.is_ipv4())
        })
        .map(|(_, ip)| SocketAddr::new(ip, local.port()))
        .collect()
}

fn interface_addrs() -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a linked list we free below with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut p = ifap;
    while !p.is_null() {
        // SAFETY: p walks the list returned by getifaddrs.
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_flags & (libc::IFF_UP as u32) == 0 {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        // SAFETY: the family field is valid for every sockaddr; the cast matches the family.
        let ip = unsafe {
            match (*ifa.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
                }
                _ => continue,
            }
        };
        out.push((name, ip));
    }
    // SAFETY: ifap came from getifaddrs.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specific_and_wildcard() {
        assert_eq!(host_candidates("10.0.0.2:5000".parse().unwrap()), vec!["10.0.0.2:5000".parse().unwrap()]);
        assert!(host_candidates("[fd00::1]:5".parse().unwrap()).is_empty());
        assert!(host_candidates("169.254.1.1:5".parse().unwrap()).is_empty());
        for c in host_candidates("0.0.0.0:6000".parse().unwrap()) {
            assert!(c.is_ipv4() && !c.ip().is_loopback() && c.port() == 6000, "{c}");
        }
        // This machine has docker0 (172.17.0.1): it must never be offered.
        let all = host_candidates("[::]:7000".parse().unwrap());
        let bridges: Vec<_> = interface_addrs()
            .into_iter()
            .filter(|(n, _)| BRIDGE_PREFIXES.iter().any(|p| n.starts_with(p)))
            .map(|(_, ip)| ip)
            .collect();
        for c in &all {
            assert!(!bridges.contains(&c.ip()), "bridge address offered: {c}");
        }
    }
}
