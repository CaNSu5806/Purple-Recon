from html import escape


def build_html_report(report):
    """
    Build a simple HTML security report from the unified PurpleRecon report.

    The first version intentionally uses plain HTML so that the reporting
    layer remains easy to understand and extend later.
    """

    metadata = report.get("metadata", {})
    summary = report.get("summary", {})
    scan = report.get("scan", {})
    risk_findings = report.get("risk_findings", [])
    attack_mappings = report.get("attack_mappings", [])

    target = escape(str(metadata.get("target", "unknown")))
    generated_at = escape(str(metadata.get("generated_at", "unknown")))

    # Build the open-port table rows.
    port_rows = ""

    for port in scan.get("ports", []):
        port_rows += f"""
        <tr>
            <td>{escape(str(port.get("port")))}</td>
            <td>{escape(str(port.get("protocol")))}</td>
            <td>{escape(str(port.get("service")))}</td>
            <td>{escape(str(port.get("product")))}</td>
            <td>{escape(str(port.get("version")))}</td>
        </tr>
        """

    # Build the risk-finding table rows.
    risk_rows = ""

    for finding in risk_findings:
        risk_rows += f"""
        <tr>
            <td>{escape(str(finding.get("port")))}</td>
            <td>{escape(str(finding.get("service")))}</td>
            <td>{escape(str(finding.get("risk")))}</td>
            <td>{escape(str(finding.get("reason")))}</td>
        </tr>
        """

    # Build the ATT&CK mapping table rows.
    attack_rows = ""

    for mapping in attack_mappings:
        attack_rows += f"""
        <tr>
            <td>{escape(str(mapping.get("service")))}</td>
            <td>{escape(str(mapping.get("technique_id")))}</td>
            <td>{escape(str(mapping.get("technique_name")))}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>PurpleRecon Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}

        th,
        td {{
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
        }}

        th {{
            background-color: #f2f2f2;
        }}

        .summary {{
            margin-bottom: 30px;
        }}
    </style>
</head>

<body>

    <h1>PurpleRecon Security Report</h1>

    <p>
        <strong>Target:</strong> {target}<br>
        <strong>Generated:</strong> {generated_at}
    </p>

    <div class="summary">
        <h2>Summary</h2>

        <p>
            Host status: {escape(str(summary.get("host_status")))}<br>
            Open ports: {summary.get("open_port_count", 0)}<br>
            Security events: {summary.get("event_count", 0)}<br>
            Risk findings: {summary.get("risk_finding_count", 0)}<br>
            ATT&CK mappings: {summary.get("attack_mapping_count", 0)}
        </p>
    </div>

    <h2>Discovered Services</h2>

    <table>
        <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>Service</th>
            <th>Product</th>
            <th>Version</th>
        </tr>

        {port_rows}

    </table>

    <h2>Risk Findings</h2>

    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Risk</th>
            <th>Reason</th>
        </tr>

        {risk_rows}

    </table>

    <h2>MITRE ATT&CK Context</h2>

    <table>
        <tr>
            <th>Service</th>
            <th>Technique ID</th>
            <th>Technique</th>
        </tr>

        {attack_rows}

    </table>

</body>

</html>
"""

    return html