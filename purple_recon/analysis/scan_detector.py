from collections import defaultdict


def detect_scan_patterns(packets, syn_threshold=5):
    """
    Detect simple TCP SYN scan patterns from parsed packet data.

    A source IP is flagged when it sends SYN packets to several
    different destination ports on the same target.

    Args:
        packets (list): Parsed packet dictionaries.
        syn_threshold (int): Minimum number of distinct destination
                             ports required to create a finding.

    Returns:
        list: Detected scan-pattern findings.
    """

    findings = []

    # Structure:
    # (source_ip, destination_ip) -> set(destination_ports)
    syn_activity = defaultdict(set)

    for packet in packets:
        # We only care about TCP packets with SYN flags.
        if packet.get("protocol") != "TCP":
            continue

        if packet.get("tcp_flags") != "0x0002":
            continue

        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        destination_port = packet.get("destination_port")

        # Skip incomplete packets.
        if not source_ip or not destination_ip or destination_port is None:
            continue

        syn_activity[(source_ip, destination_ip)].add(destination_port)

    # Evaluate the collected SYN activity.
    for (source_ip, destination_ip), ports in syn_activity.items():
        if len(ports) < syn_threshold:
            continue

        finding = {
            "event_type": "possible_syn_scan",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "distinct_destination_ports": len(ports),
            "ports": sorted(ports),
            "severity": "medium",
            "reason": (
                f"Source contacted {len(ports)} distinct TCP ports "
                "using SYN packets."
            )
        }

        findings.append(finding)

    return findings