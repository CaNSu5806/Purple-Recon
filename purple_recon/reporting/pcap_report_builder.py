from pathlib import Path


def build_pcap_report(pcap_path, packets, findings):
    """
    Build a structured defensive report from PCAP analysis results.

    Args:
        pcap_path (str): Path to the analyzed capture file.
        packets (list): Normalized packets produced by the PCAP parser.
        findings (list): Reconnaissance patterns detected in the capture.

    Returns:
        dict: Structured PCAP analysis report.
    """

    capture_name = Path(pcap_path).name

    # Count protocols observed in the capture.
    protocol_counts = {}

    for packet in packets:
        protocol = packet.get("protocol")

        if not protocol:
            continue

        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    report = {
        "analysis_type": "pcap",
        "capture_file": capture_name,

        "summary": {
            "total_packets": len(packets),
            "total_findings": len(findings),
            "protocols": protocol_counts
        },

        "findings": findings
    }

    return report