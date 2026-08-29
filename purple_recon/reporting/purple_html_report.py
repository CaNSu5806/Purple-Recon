from html import escape


def build_purple_html_report(report):
    """
    Build a human-readable HTML report for the PurpleRecon
    correlation workflow.

    Args:
        report (dict): Unified Purple Team correlation report.

    Returns:
        str: Complete HTML document.
    """

    target = escape(str(report.get("target", "Unknown")))

    reconnaissance = report.get("reconnaissance", {})
    defensive = report.get("defensive_analysis", {})
    correlation = report.get("correlation", {})

    scan_data = reconnaissance.get("scan", {})
    risk_findings = reconnaissance.get("risk_findings", [])
    attack_mappings = reconnaissance.get("attack_mappings", [])

    scan_findings = defensive.get("scan_findings", [])
    packet_count = defensive.get("packet_count", 0)

    correlation_results = correlation.get("results", [])
    total_matches = correlation.get("total_matches", 0)

    # -------------------------
    # Open services
    # -------------------------

    service_rows = ""

    for service in scan_data.get("ports", []):
        service_rows += f"""
        <tr>
            <td>{escape(str(service.get("port", "-")))}</td>
            <td>{escape(str(service.get("protocol", "-")))}</td>
            <td>{escape(str(service.get("service", "-")))}</td>
            <td>{escape(str(service.get("product") or "-"))}</td>
            <td>{escape(str(service.get("version") or "-"))}</td>
        </tr>
        """

    if not service_rows:
        service_rows = """
        <tr>
            <td colspan="5">No open services discovered.</td>
        </tr>
        """

    # -------------------------
    # Risk findings
    # -------------------------

    risk_rows = ""

    for finding in risk_findings:
        risk_rows += f"""
        <tr>
            <td>{escape(str(finding.get("port", "-")))}</td>
            <td>{escape(str(finding.get("service", "-")))}</td>
            <td>{escape(str(finding.get("severity", "-")))}</td>
            <td>{escape(str(finding.get("reason", "-")))}</td>
        </tr>
        """

    if not risk_rows:
        risk_rows = """
        <tr>
            <td colspan="4">No contextual risk findings.</td>
        </tr>
        """

    # -------------------------
    # PCAP findings
    # -------------------------

    pcap_rows = ""

    for finding in scan_findings:
        ports = ", ".join(
            str(port) for port in finding.get("ports", [])
        )

        pcap_rows += f"""
        <tr>
            <td>{escape(str(finding.get("event_type", "-")))}</td>
            <td>{escape(str(finding.get("source_ip", "-")))}</td>
            <td>{escape(str(finding.get("destination_ip", "-")))}</td>
            <td>{escape(ports or "-")}</td>
            <td>{escape(str(finding.get("severity", "-")))}</td>
        </tr>
        """

    if not pcap_rows:
        pcap_rows = """
        <tr>
            <td colspan="5">No reconnaissance pattern detected in the capture.</td>
        </tr>
        """

    # -------------------------
    # Correlations
    # -------------------------

    correlation_rows = ""

    for result in correlation_results:
        matched_ports = ", ".join(
            str(port) for port in result.get("matched_ports", [])
        )

        correlation_rows += f"""
        <tr>
            <td>{escape(str(result.get("source_ip", "-")))}</td>
            <td>{escape(str(result.get("destination_ip", "-")))}</td>
            <td>{escape(matched_ports or "-")}</td>
            <td>{escape(str(result.get("matched_port_count", 0)))}</td>
        </tr>
        """

    if not correlation_rows:
        correlation_rows = """
        <tr>
            <td colspan="4">No Nmap/PCAP correlations identified.</td>
        </tr>
        """

    # -------------------------
    # HTML document
    # -------------------------

    return f"""<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PurpleRecon Report - {target}</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #111318;
            color: #e8e8e8;
            margin: 0;
            padding: 40px;
        }}

        .container {{
            max-width: 1200px;
            margin: auto;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        h2 {{
            margin-top: 40px;
            border-bottom: 1px solid #444;
            padding-bottom: 10px;
        }}

        .subtitle {{
            color: #aaa;
        }}

        .summary {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 30px;
        }}

        .card {{
            background: #1c1f26;
            padding: 20px;
            border-radius: 8px;
            min-width: 180px;
        }}

        .value {{
            font-size: 28px;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #1c1f26;
        }}

        th, td {{
            padding: 12px;
            border-bottom: 1px solid #333;
            text-align: left;
        }}

        th {{
            background: #252934;
        }}

        .footer {{
            margin-top: 50px;
            color: #777;
            font-size: 13px;
        }}
    </style>
</head>

<body>

<div class="container">

    <h1>PurpleRecon</h1>

    <div class="subtitle">
        Purple Team Reconnaissance & Detection Correlation Report
    </div>

    <h2>Executive Summary</h2>

    <p>
        Target: <strong>{target}</strong>
    </p>

    <div class="summary">

        <div class="card">
            <div>Open Services</div>
            <div class="value">
                {len(scan_data.get("ports", []))}
            </div>
        </div>

        <div class="card">
            <div>Captured Packets</div>
            <div class="value">
                {packet_count}
            </div>
        </div>

        <div class="card">
            <div>PCAP Findings</div>
            <div class="value">
                {len(scan_findings)}
            </div>
        </div>

        <div class="card">
            <div>Correlations</div>
            <div class="value">
                {total_matches}
            </div>
        </div>

    </div>

    <h2>Offensive Reconnaissance</h2>

    <table>
        <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>Service</th>
            <th>Product</th>
            <th>Version</th>
        </tr>

        {service_rows}

    </table>

    <h2>Risk Analysis</h2>

    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Severity</th>
            <th>Reason</th>
        </tr>

        {risk_rows}

    </table>

    <h2>Defensive PCAP Analysis</h2>

    <table>
        <tr>
            <th>Event</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Observed Ports</th>
            <th>Severity</th>
        </tr>

        {pcap_rows}

    </table>

    <h2>Offensive / Defensive Correlation</h2>

    <table>
        <tr>
            <th>Source</th>
            <th>Destination</th>
            <th>Matched Ports</th>
            <th>Matches</th>
        </tr>

        {correlation_rows}

    </table>

    <div class="footer">
        Generated by PurpleRecon
    </div>

</div>

</body>
</html>
"""