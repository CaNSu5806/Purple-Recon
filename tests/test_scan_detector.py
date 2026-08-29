from purple_recon.analysis.scan_detector import detect_scan_patterns


def test_detect_syn_scan():
    packets = [
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "destination_port": 22,
            "tcp_flags": "0x0002"
        },
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "destination_port": 80,
            "tcp_flags": "0x0002"
        },
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "destination_port": 443,
            "tcp_flags": "0x0002"
        }
    ]

    findings = detect_scan_patterns(
        packets,
        syn_threshold=3
    )

    assert len(findings) == 1
    assert findings[0]["event_type"] == "possible_syn_scan"
    assert findings[0]["source_ip"] == "10.0.0.5"
    assert findings[0]["destination_ip"] == "10.0.0.10"
    assert findings[0]["distinct_destination_ports"] == 3
    assert findings[0]["ports"] == [22, 80, 443]
    
def test_normal_tcp_activity_is_not_detected_as_scan():
    """
    Normal TCP activity involving only a few destination ports
    should not be classified as a SYN scan.
    """

    packets = [
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "destination_port": 80,
            "tcp_flags": "0x0002"
        },
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "destination_port": 443,
            "tcp_flags": "0x0002"
        }
    ]

    findings = detect_scan_patterns(
        packets,
        syn_threshold=5
    )

    assert findings == []
    
def test_repeated_syn_packets_to_same_port_are_not_scan():
    """
    Repeated SYN packets to the same destination port should
    count as one distinct port rather than multiple scan attempts.
    """

    packets = [
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "destination_port": 443,
            "tcp_flags": "0x0002"
        }
        for _ in range(10)
    ]

    findings = detect_scan_patterns(
        packets,
        syn_threshold=5
    )

    assert findings == []