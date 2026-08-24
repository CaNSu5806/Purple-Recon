from datetime import datetime, timezone


def build_report(scan_data, events, risk_findings, attack_mappings):
    """
    Build a single PurpleRecon report from all analysis layers.

    The report combines:
    - raw structured scan data
    - normalized security events
    - contextual risk findings
    - MITRE ATT&CK context mappings
    """

    report = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "PurpleRecon",
            "target": scan_data.get("target")
        },

        "summary": {
            "host_status": scan_data.get("status"),
            "open_port_count": len(scan_data.get("ports", [])),
            "event_count": len(events),
            "risk_finding_count": len(risk_findings),
            "attack_mapping_count": len(attack_mappings)
        },

        "scan": scan_data,
        "events": events,
        "risk_findings": risk_findings,
        "attack_mappings": attack_mappings
    }

    return report