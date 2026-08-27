def parse_tshark_output(raw_output):
    """
    Convert tab-separated TShark output into structured packet data.

    Expected field order:
    timestamp, source IP, destination IP, protocol,
    source port, destination port, TCP flags
    """

    packets = []

    # Process the TShark output line by line.
    for line in raw_output.splitlines():

        # Ignore empty lines.
        if not line.strip():
            continue

        fields = line.split("\t")

        # TShark may return missing values for non-IP or non-TCP packets.
        # Ensure the list always has seven fields.
        while len(fields) < 7:
            fields.append("")

        timestamp = fields[0]
        source_ip = fields[1]
        destination_ip = fields[2]
        protocol = fields[3]
        source_port = fields[4]
        destination_port = fields[5]
        tcp_flags = fields[6]

        packet = {
            "timestamp": timestamp or None,
            "source_ip": source_ip or None,
            "destination_ip": destination_ip or None,
            "protocol": protocol or None,
            "source_port": int(source_port) if source_port.isdigit() else None,
            "destination_port": int(destination_port) if destination_port.isdigit() else None,
            "tcp_flags": tcp_flags or None
        }

        packets.append(packet)

    return packets