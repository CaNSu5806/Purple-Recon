def map_attack_context(scan_data):
    """
    Map discovered services to relevant MITRE ATT&CK context.

    This does not mean an ATT&CK technique was actually executed.
    It only provides contextual information about services that may
    relate to known remote-service or discovery techniques.
    """

    mappings = []

    # Initial service-to-ATT&CK context rules.
    service_map = {
        "microsoft-ds": {
            "technique_id": "T1021.002",
            "technique_name": "SMB/Windows Admin Shares"
        },
        "mysql": {
            "technique_id": "T1021",
            "technique_name": "Remote Services"
        },
        "oracle-tns": {
            "technique_id": "T1021",
            "technique_name": "Remote Services"
        },
        "ssh": {
            "technique_id": "T1021.004",
            "technique_name": "SSH"
        },
        "rdp": {
            "technique_id": "T1021.001",
            "technique_name": "Remote Desktop Protocol"
        }
    }

    for port in scan_data.get("ports", []):

        if port.get("state") != "open":
            continue

        service = port.get("service")

        if service not in service_map:
            continue

        technique = service_map[service]

        mapping = {
            "target": scan_data.get("target"),
            "port": port.get("port"),
            "service": service,
            "technique_id": technique["technique_id"],
            "technique_name": technique["technique_name"],
            "context": "Potential ATT&CK relevance based on exposed service"
        }

        mappings.append(mapping)

    return mappings