import argparse
import json

from purple_recon.recon.nmap import run_nmap
from purple_recon.parsers.nmap_parser import parse_nmap_xml
from purple_recon.generators.event_generator import generate_security_events
from purple_recon.analysis.risk_analyzer import analyze_risk
from purple_recon.reporting.html_report import build_html_report
from purple_recon.utils.output_manager import save_json, save_html
from purple_recon.analysis.attack_mapper import map_attack_context
from purple_recon.reporting.report_builder import build_report
from purple_recon.utils.config_loader import load_config
from purple_recon.recon.tshark import analyze_pcap
from purple_recon.parsers.pcap_parser import parse_tshark_output
from purple_recon.analysis.scan_detector import detect_scan_patterns

def run_scan(target):
    """
    Run the complete PurpleRecon scanning workflow.
    """

    print("[*] PurpleRecon")

    # Load PurpleRecon settings from config.yaml.
    config = load_config()

    # Run Nmap using scanner settings from the configuration file.
    xml_output = run_nmap(
        target,
        config["scanner"]
    )

    if not xml_output:
        return

    # Convert raw Nmap XML into structured scan data.
    scan_data = parse_nmap_xml(xml_output)

    # Convert discovered open services into normalized security events.
    events = generate_security_events(scan_data)

    # Analyze discovered services for contextual risk.
    risk_findings = analyze_risk(scan_data)

    # Add MITRE ATT&CK context to discovered services.
    attack_mappings = map_attack_context(scan_data)

    # Build a unified report containing all analysis layers.
    report = build_report(
        scan_data,
        events,
        risk_findings,
        attack_mappings
    )
    # Convert the unified report into a human-readable HTML report.
    html_report = build_html_report(report)

    print("[+] Scan completed successfully.\n")

    # Show structured scan results in the terminal.
    print(json.dumps(scan_data, indent=4))

    print("\n[+] Risk findings:")
    print(json.dumps(risk_findings, indent=4))

    # Use the parsed target value for generated output filenames.
    target_value = scan_data.get("target")

    # Save each PurpleRecon data layer separately.
    scan_filepath = save_json(
        scan_data,
        target_value,
        "scan"
    )

    events_filepath = save_json(
        events,
        target_value,
        "events"
    )

    risk_filepath = save_json(
        risk_findings,
        target_value,
        "risk"
    )

    attack_filepath = save_json(
        attack_mappings,
        target_value,
        "attack"
    )

    report_filepath = save_json(
        report,
        target_value,
        "report"
    )
    html_filepath = save_html(
    html_report,
    target_value
    )

    print(f"\n[+] Scan results saved to {scan_filepath}")
    print(f"[+] Security events saved to {events_filepath}")
    print(f"[+] Risk findings saved to {risk_filepath}")
    print(f"[+] ATT&CK context saved to {attack_filepath}")
    print(f"[+] Unified report saved to {report_filepath}")
    print(f"[+] HTML report saved to {html_filepath}")
    
def run_pcap_analysis(pcap_path):
    """
    Run the PurpleRecon defensive PCAP analysis workflow.

    This workflow reads a capture file with TShark, converts
    the raw output into structured packet data, and searches
    for basic reconnaissance patterns.
    """

    print("[*] PurpleRecon - PCAP Analysis")
    print(f"[*] Capture: {pcap_path}")

    # Extract selected network fields from the capture using TShark.
    raw_output = analyze_pcap(pcap_path)

    if not raw_output:
        print("[!] No packet data could be extracted.")
        return

    # Convert raw TShark output into normalized packet dictionaries.
    packets = parse_tshark_output(raw_output)

    print(f"[+] Parsed {len(packets)} packets.")

    # Analyze TCP activity for possible reconnaissance patterns.
    findings = detect_scan_patterns(packets)

    print("\n[+] Scan detection findings:")
    print(json.dumps(findings, indent=4))


def main():
    """
    PurpleRecon command-line interface.
    """

    parser = argparse.ArgumentParser(
        description="PurpleRecon - Purple-Team Reconnaissance and Detection Tool"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # -------------------------
    # Active Reconnaissance
    # -------------------------

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run an Nmap reconnaissance scan"
    )

    scan_parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    # -------------------------
    # Defensive PCAP analysis
    # -------------------------

    pcap_parser = subparsers.add_parser(
        "analyze-pcap",
        help="Analyze a PCAP/PCAPNG capture file"
    )

    pcap_parser.add_argument(
        "pcap",
        help="Path to the PCAP or PCAPNG file"
    )

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args.target)

    elif args.command == "analyze-pcap":
        run_pcap_analysis(args.pcap)


if __name__ == "__main__":
    main()