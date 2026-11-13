"""
HomeSOC IP context.

Classifies addresses locally.
Public does not mean malicious.
Private does not mean trusted.
"""

import ipaddress


PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def classify_ip(value):
    """Return an address category without changing risk scores."""

    if value is None or str(value).strip() == "":
        return "Missing"

    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "Invalid"

    # Classify IPv4-mapped IPv6 by its underlying IPv4 address.
    if isinstance(address, ipaddress.IPv6Address):
        address = address.ipv4_mapped or address

    if address.is_unspecified:
        return "Unspecified"

    if address.is_loopback:
        return "Loopback"

    if address.is_link_local:
        return "Link-local"

    if address.is_multicast:
        return "Multicast"

    if any(
        address.version == network.version and address in network
        for network in PRIVATE_NETWORKS
    ):
        return "Private"

    if address.is_global:
        return "Public"

    return "Non-public"


def enrich_event(event):
    """Return an enriched copy, preserving the original event."""

    enriched = event.copy()

    enriched["src_ip_type"] = classify_ip(event.get("src_ip"))
    enriched["dst_ip_type"] = classify_ip(event.get("dst_ip"))
    enriched["asset_ip_type"] = classify_ip(
        event.get("asset_ip") or event.get("dst_ip")
    )

    return enriched


if __name__ == "__main__":
    cases = [
        ("192.168.1.50", "Private"),
        ("8.8.8.8", "Public"),
        ("127.0.0.1", "Loopback"),
        ("169.254.1.10", "Link-local"),
        ("224.0.0.1", "Multicast"),
        ("0.0.0.0", "Unspecified"),
        ("192.0.2.10", "Non-public"),
        ("::1", "Loopback"),
        ("fd00::1", "Private"),
        ("::ffff:192.168.1.50", "Private"),
        ("not-an-ip", "Invalid"),
        (None, "Missing"),
    ]

    for value, expected in cases:
        actual = classify_ip(value)
        assert actual == expected, (
            f"{value}: expected {expected}, got {actual}"
        )
        print(f"{str(value):<28} {actual}")

    original = {
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
        "risk_score": 35,
    }
    enriched = enrich_event(original)

    assert enriched["risk_score"] == 35
    assert enriched["asset_ip_type"] == "Public"
    assert "src_ip_type" not in original

    print("\nVALIDATION PASSED")