from purple_recon.generators.event_generator import generate_security_events


def test_generate_security_events():
    """
    Verify that security events are generated only for open ports.
    """

    # Fake parsed scan data.
    sample_scan = {
        "target": "127.0.0.1",
        "status": "up",
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.0"
            },
            {
                "port": 80,
                "protocol": "tcp",
                "state": "closed",
                "service": "http",
                "product": "Apache",
                "version": "2.4"
            }
        ]
    }

    events = generate_security_events(sample_scan)

    # Only the open SSH port should generate an event.
    assert len(events) == 1

    event = events[0]

    assert event["event_type"] == "service_discovery"
    assert event["target"] == "127.0.0.1"
    assert event["port"] == 22
    assert event["protocol"] == "tcp"
    assert event["service"] == "ssh"
    assert event["product"] == "OpenSSH"
    assert event["version"] == "9.0"
    assert event["severity"] == "info"

    # Timestamp should exist.
    assert "timestamp" in event