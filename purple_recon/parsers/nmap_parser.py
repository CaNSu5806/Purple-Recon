import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_output):
    """
    Converts raw Nmap XML output into a structured Python dictionary.

    Only the information currently needed by PurpleRecon is extracted.
    Additional Nmap fields can be added here later as the project grows.
    """

    # Convert the XML string returned by Nmap into an XML tree.
    root = ET.fromstring(xml_output)

    # Standard structure returned even when no host information is found.
    scan_data = {
        "target": None,
        "status": None,
        "ports": []
    }

    host = root.find("host")

    if host is None:
        return scan_data

    # Extract the scanned host's address.
    address = host.find("address")
    if address is not None:
        scan_data["target"] = address.get("addr")

    # Determine whether Nmap considers the host up or down.
    status = host.find("status")
    if status is not None:
        scan_data["status"] = status.get("state")

    ports = host.find("ports")

    if ports is not None:

        # Each <port> element represents one scanned port.
        for port in ports.findall("port"):
            state = port.find("state")
            service = port.find("service")

            port_data = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None
            }

            scan_data["ports"].append(port_data)

    return scan_data