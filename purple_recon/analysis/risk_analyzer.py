def analyze_risk(scan_data):
    
    """
    Analyze discovered services and produce basic risk findings.

    This module does not claim that an open port is a vulnerability.
    It only adds contextual risk information based on exposed services.
    """

    findings = []

    # Services that are commonly more sensitive when exposed.
    sensitive_services = {
        "ftp": "medium",
        "telnet": "high",
        "mysql": "medium",
        "ms-sql-s": "medium",
        "oracle-tns": "medium",
        "microsoft-ds": "medium"
    }

    for port in scan_data.get("ports", []):

        # Ignore ports that are not open.
        if port.get("state") != "open":
            continue

        service = port.get("service")

        # If the discovered service is not in our current rule set,
        # we do not assign a risk finding yet.
        if service not in sensitive_services:
            continue

        finding = {
            "target": scan_data.get("target"),
            "port": port.get("port"),
            "service": service,
            "product": port.get("product"),
            "version": port.get("version"),
            "risk": sensitive_services[service],
            "reason": f"{service} service is exposed and may require review"
        }

        findings.append(finding)

    return findings