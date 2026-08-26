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

def main():
    """
    Configure and handle the PurpleRecon command-line interface.
    """

    parser = argparse.ArgumentParser(
        description="PurpleRecon - Automated Purple-Team Recon Tool"
    )

    # Create subcommands such as scan, analyze, report, etc.
    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands"
    )

    # Create the "scan" command.
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run reconnaissance against a target"
    )

    # The scan command requires a target.
    scan_parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    args = parser.parse_args()

    # Run the correct workflow based on the selected command.
    if args.command == "scan":
        run_scan(args.target)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()