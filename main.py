import argparse
import json
import os
from datetime import datetime

from purple_recon.scanner import run_nmap
from purple_recon.parser import parse_nmap_xml
from purple_recon.event_generator import generate_security_events


def save_scan_result(scan_data):
    os.makedirs("output", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    target = scan_data.get("target") or "unknown"

    filename = f"scan_{target}_{timestamp}.json"
    filepath = os.path.join("output", filename)

    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(scan_data, file, indent=4)

    return filepath

def save_security_events(events, target):
    """
    Save generated security events as a JSON file.

    Event files are stored separately from raw scan results so they
    can later be consumed by SIEM or analysis components.
    """

    os.makedirs("output", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    target = target or "unknown"

    filename = f"events_{target}_{timestamp}.json"
    filepath = os.path.join("output", filename)

    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)

    return filepath

def main():
    parser = argparse.ArgumentParser(
        description="PurpleRecon - Automated Purple-Team Recon Tool"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    args = parser.parse_args()

    print("[*] PurpleRecon")

    # Run Nmap and collect its XML output.
    xml_output = run_nmap(args.target)

    if xml_output:
        # Convert raw Nmap XML into structured scan data.
        scan_data = parse_nmap_xml(xml_output)

        # Convert discovered open services into normalized security events.
        events = generate_security_events(scan_data)

        print("[+] Scan completed successfully.\n")
        print(json.dumps(scan_data, indent=4))

        # Store scan results and generated events separately.
        filepath = save_scan_result(scan_data)

        events_filepath = save_security_events(
            events,
            scan_data.get("target")
        )

        print(f"\n[+] Scan results saved to {filepath}")
        print(f"[+] Security events saved to {events_filepath}")

if __name__ == "__main__":
    main()