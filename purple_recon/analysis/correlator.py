def correlate_recon_and_pcap(scan_data, pcap_findings):
    """
    Correlate Nmap reconnaissance results with PCAP scan findings.

    This function compares ports observed in network scan activity
    with ports confirmed as open by Nmap.

    Args:
        scan_data (dict): Parsed Nmap scan results.
        pcap_findings (list): Findings produced by the PCAP scan detector.

    Returns:
        list: Correlation results.
    """

    correlations = []

    # Collect ports that Nmap confirmed as open.
    open_ports = {
        port.get("port")
        for port in scan_data.get("ports", [])
        if port.get("state") == "open"
    }

    for finding in pcap_findings:
        if finding.get("event_type") != "possible_syn_scan":
            continue

        observed_ports = set(
            finding.get("ports", [])
        )

        # Ports that appear both in the PCAP scan pattern
        # and in Nmap's confirmed open-port results.
        matched_ports = sorted(
            observed_ports.intersection(open_ports)
        )

        correlation = {
            "source_ip": finding.get("source_ip"),
            "destination_ip": finding.get("destination_ip"),

            "observed_scan_ports": sorted(observed_ports),

            "confirmed_open_ports": sorted(open_ports),

            "matched_ports": matched_ports,

            "matched_port_count": len(matched_ports),

            "context": (
                "Ports observed in the PCAP scan pattern were compared "
                "with services confirmed as open by Nmap."
            )
        }

        correlations.append(correlation)

    return correlations