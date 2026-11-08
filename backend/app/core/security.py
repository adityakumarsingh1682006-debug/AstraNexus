import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, List, Optional
from backend.app.core.exceptions import SSRFSecurityViolation
from backend.app.core.config import settings

# Explicit IPv4 and IPv6 forbidden networks (RFC 1918, RFC 5735, RFC 3927, RFC 4291, etc.)
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # Broadcast
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS & Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),     # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),         # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),          # Multicast
]


def is_ip_allowed(ip_str: str) -> bool:
    """
    Checks if an IP address is publicly routable and NOT in private/reserved ranges.
    Returns True if safe, False if private/reserved/loopback.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False

        for network in FORBIDDEN_NETWORKS:
            if ip in network:
                return False

        return True
    except ValueError:
        return False


def validate_target_url_syntax(target_url: str) -> Tuple[str, str, Optional[str]]:
    """
    Validates URL scheme, syntax, and direct IP address boundaries without blocking on DNS failure.
    - Validates scheme is HTTP or HTTPS
    - Validates hostname exists
    - Rejects localhost loopback hostname
    - Rejects direct private/cloud-metadata IP addresses immediately
    
    Returns:
        (canonical_url, hostname, direct_ip_or_none)
    """
    if not target_url or not isinstance(target_url, str):
        raise SSRFSecurityViolation("Missing or invalid target URL")

    url = target_url.strip()
    parsed_initial = urlparse(url)
    if parsed_initial.scheme and parsed_initial.scheme not in ("http", "https"):
        raise SSRFSecurityViolation(f"Unsupported scheme '{parsed_initial.scheme}'. Only http and https are permitted.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFSecurityViolation(f"Unsupported scheme '{parsed.scheme}'. Only http and https are permitted.")

    if not parsed.hostname:
        raise SSRFSecurityViolation("Target URL does not contain a valid hostname")

    clean_host = parsed.hostname.strip().lower()
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = clean_host.split(":")[0]

    # Explicit localhost hostname block
    if clean_host == "localhost" or clean_host.endswith(".localhost"):
        raise SSRFSecurityViolation(f"Target '{clean_host}' resolves to local loopback and is blocked.")

    # Check if host is a direct IP
    try:
        ip = ipaddress.ip_address(clean_host)
        if not is_ip_allowed(str(ip)):
            raise SSRFSecurityViolation(f"Direct IP {ip} is within restricted/private address space")
        return url, clean_host, str(ip)
    except ValueError:
        pass  # It's a domain name

    return url, clean_host, None


def resolve_and_verify_safe_ips(hostname: str) -> Tuple[bool, List[str], Optional[str]]:
    """
    Resolves hostname to IP addresses and asserts that EVERY resolved IP
    is publicly routable to prevent SSRF and DNS rebinding.
    
    Returns:
        (is_resolvable, resolved_ips_list, error_or_none)
    
    Raises:
        SSRFSecurityViolation: IF the host resolves to a private/loopback/cloud-metadata IP.
    """
    if not hostname:
        return False, [], "Empty hostname"

    clean_host = hostname.strip().lower()
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = clean_host.split(":")[0]

    # If it is a direct IP
    try:
        ip = ipaddress.ip_address(clean_host)
        if not is_ip_allowed(str(ip)):
            raise SSRFSecurityViolation(f"Direct IP {ip} is within restricted/private address space")
        return True, [str(ip)], None
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = list({item[4][0] for item in addr_info})
    except socket.gaierror as e:
        # Hostname could not be resolved (NXDOMAIN or DNS unreachable)
        # This is NOT an SSRF violation against an internal network.
        return False, [], f"DNS resolution failed: {str(e)}"
    except Exception as e:
        return False, [], f"DNS lookup error: {str(e)}"

    if not resolved_ips:
        return False, [], "No IP records found for host"

    # Enforce SSRF boundary on EVERY resolved IP
    valid_resolved_ips = []
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_unspecified:
                # 0.0.0.0 or :: indicates a DNS sinkhole or non-routable host, not an internal network probe
                continue
            if not is_ip_allowed(ip_str):
                raise SSRFSecurityViolation(
                    f"Host {clean_host} resolved to restricted IP {ip_str}. Access blocked to prevent SSRF."
                )
            valid_resolved_ips.append(ip_str)
        except ValueError:
            raise SSRFSecurityViolation(f"Host {clean_host} returned malformed IP {ip_str}")

    if not valid_resolved_ips:
        return False, [], f"Host {clean_host} resolved only to non-routable sinkhole address ({', '.join(resolved_ips)})"

    return True, valid_resolved_ips, None


def validate_target_url(target_url: str) -> Tuple[str, str, List[str]]:
    """
    Standard backward-compatible validator.
    Ensures safe syntax and verifies that if DNS resolves, IPs are strictly public.
    If DNS fails to resolve, returns empty list of IPs so investigation can proceed.
    """
    canonical_url, hostname, direct_ip = validate_target_url_syntax(target_url)

    if direct_ip:
        return canonical_url, hostname, [direct_ip]

    is_resolvable, resolved_ips, _ = resolve_and_verify_safe_ips(hostname)
    return canonical_url, hostname, resolved_ips
