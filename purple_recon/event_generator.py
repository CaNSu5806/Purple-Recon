from datetime import datetime, timezone


def generate_security_events(scan_data):
    """
    Converts parsed Nmap findings into normalized security events.

    At this stage, events represent observations rather than
    vulnerabilities. Risk scoring and ATT&CK mapping will be handled
    separately later.
    """

    events = []

    target = scan_data.get("target")

    # Process every port discovered during the Nmap scan.
    for port in scan_data.get("ports", []):

        # We currently generate events only for open ports.
        # Closed/filtered ports can be supported later if useful.
        if port.get("state") != "open":
            continue

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "service_discovery",
            "target": target,
            "port": port.get("port"),
            "protocol": port.get("protocol"),
            "service": port.get("service"),
            "product": port.get("product"),
            "version": port.get("version"),

            # An open service is an observation, not automatically a threat.
            # Therefore the initial severity is informational.
            "severity": "info"
        }

        events.append(event)

    return events