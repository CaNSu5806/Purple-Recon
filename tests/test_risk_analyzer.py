from purple_recon.analysis.risk_analyzer import analyze_risk


def test_analyze_risk():
    """
    Verify that sensitive services are assigned the expected
    contextual risk levels.
    """

    # Fake parsed scan data.
    # This lets us test the risk analyzer without running Nmap.
    sample_scan = {
        "target": "127.0.0.1",
        "status": "up",
        "ports": [
            {
                "port": 23,
                "protocol": "tcp",
                "state": "open",
                "service": "telnet",
                "product": None,
                "version": None
            },
            {
                "port": 3306,
                "protocol": "tcp",
                "state": "open",
                "service": "mysql",
                "product": "MySQL",
                "version": "8.0"
            },
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "Apache",
                "version": "2.4"
            }
        ]
    }

    result = analyze_risk(sample_scan)

    # Only telnet and mysql currently exist in our risk rule set.
    # HTTP should therefore not create a finding.
    assert len(result) == 2

    telnet_finding = result[0]
    mysql_finding = result[1]

    # Telnet is currently classified as high risk.
    assert telnet_finding["service"] == "telnet"
    assert telnet_finding["risk"] == "high"

    # MySQL is currently classified as medium risk.
    assert mysql_finding["service"] == "mysql"
    assert mysql_finding["risk"] == "medium"