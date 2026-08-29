from purple_recon.analysis.correlator import correlate_recon_and_pcap


def test_correlate_recon_and_pcap():
    """
    Verify that PCAP-observed scan ports are correctly matched
    against ports confirmed as open by Nmap.
    """

    scan_data = {
        "target": "10.0.0.10",
        "status": "up",
        "ports": [
            {
                "port": 22,
                "state": "open"
            },
            {
                "port": 80,
                "state": "open"
            },
            {
                "port": 3306,
                "state": "open"
            }
        ]
    }

    pcap_findings = [
        {
            "event_type": "possible_syn_scan",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "ports": [22, 80, 443, 445]
        }
    ]

    correlations = correlate_recon_and_pcap(
        scan_data,
        pcap_findings
    )

    assert len(correlations) == 1

    result = correlations[0]

    assert result["source_ip"] == "10.0.0.5"
    assert result["destination_ip"] == "10.0.0.10"

    assert result["matched_ports"] == [22, 80]
    assert result["matched_port_count"] == 2