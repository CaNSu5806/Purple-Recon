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
from purple_recon.reporting.pcap_report_builder import build_pcap_report
from purple_recon.analysis.correlator import correlate_recon_and_pcap
from purple_recon.reporting.purple_html_report import build_purple_html_report


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
    
    # Generate the offensive/reconnaissance analysis layers.
    events = generate_security_events(scan_data)
    risk_findings = analyze_risk(scan_data)
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
    """

    print("[*] PurpleRecon - PCAP Analysis")
    print(f"[*] Capture: {pcap_path}")

    raw_output = analyze_pcap(pcap_path)

    if not raw_output:
        print("[!] No packet data could be extracted.")
        return

    packets = parse_tshark_output(raw_output)

    print(f"[+] Parsed {len(packets)} packets.")

    findings = detect_scan_patterns(packets)

    # Build a high-level defensive report from the analyzed capture.
    pcap_report = build_pcap_report(
    pcap_path,
    packets,
    findings
    )
    
    print("\n[+] Scan detection findings:")
    print(json.dumps(findings, indent=4))

    # Save parsed packet data and findings separately.
    pcap_data_filepath = save_json(
        packets,
        "pcap",
        "pcap_packets"
    )

    pcap_findings_filepath = save_json(
        findings,
        "pcap",
        "pcap_findings"
    )
    
    pcap_report_filepath = save_json(
        pcap_report,
        "pcap",
        "pcap_report"
    )
    
    purple_report_filepath = save_json(
        purple_report,
        target_value,
        "purple_report"
    )

    print(f"\n[+] Parsed packet data saved to {pcap_data_filepath}")
    print(f"[+] PCAP findings saved to {pcap_findings_filepath}")
    print(f"[+] PCAP report saved to {pcap_report_filepath}")

def run_correlation(target, pcap_path):
    """
    Run the PurpleRecon correlation workflow.

    This workflow combines active reconnaissance results from Nmap
    with defensive observations extracted from a PCAP capture.
    """

    print("[*] PurpleRecon - Correlation")
    print(f"[*] Target: {target}")
    print(f"[*] Capture: {pcap_path}")

    # Load PurpleRecon configuration.
    config = load_config()

    # -------------------------
    # Nmap reconnaissance
    # -------------------------

    xml_output = run_nmap(
        target,
        config["scanner"]
    )

    if not xml_output:
        print("[!] Nmap data could not be collected.")
        return

    # Convert raw Nmap XML into structured data.
    scan_data = parse_nmap_xml(xml_output)

    # Generate the reconnaissance analysis layers that will
    # later be included in the unified Purple Team report.
    events = generate_security_events(scan_data)
    risk_findings = analyze_risk(scan_data)
    attack_mappings = map_attack_context(scan_data)

    # -------------------------
    # PCAP analysis
    # -------------------------

    raw_output = analyze_pcap(pcap_path)

    if not raw_output:
        print("[!] PCAP data could not be extracted.")
        return

    # Normalize packet information extracted by TShark.
    packets = parse_tshark_output(raw_output)

    # Search the captured traffic for reconnaissance patterns.
    pcap_findings = detect_scan_patterns(packets)

    # -------------------------
    # Correlation
    # -------------------------

    correlations = correlate_recon_and_pcap(
        scan_data,
        pcap_findings
    )

    # -------------------------
    # Unified Purple Report
    # -------------------------

    purple_report = {
        "report_type": "purple_team_correlation",
        "target": scan_data.get("target") or target,

        "reconnaissance": {
            "scan": scan_data,
            "security_events": events,
            "risk_findings": risk_findings,
            "attack_mappings": attack_mappings
        },

        "defensive_analysis": {
            "capture_file": pcap_path,
            "packet_count": len(packets),
            "scan_findings": pcap_findings
        },

        "correlation": {
            "total_matches": len(correlations),
            "results": correlations
        }
    }
    # Convert the unified Purple Team report into HTML.
    purple_html_report = build_purple_html_report(
        purple_report
    )

    print("\n[+] Correlation results:")
    print(json.dumps(correlations, indent=4))

    # Use the parsed target whenever possible.
    target_value = scan_data.get("target") or target

    # Save the raw correlation layer.
    correlation_filepath = save_json(
        correlations,
        target_value,
        "correlation"
    )

    # Save the complete offensive + defensive report.
    purple_report_filepath = save_json(
        purple_report,
        target_value,
        "purple_report"
    )
    
    purple_report_filepath = save_json(
        purple_report,
        target_value,
        "purple_report"
    )
    
    purple_html_filepath = save_html(
        purple_html_report,
        target_value,
        "purple_report"
    )

    print(
        f"\n[+] Correlation results saved to "
        f"{correlation_filepath}"
    )

    print(
        f"[+] Unified Purple Team report saved to "
        f"{purple_report_filepath}"
    )
    
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
    
    # -------------------------
    # Purple-team correlation
    # -------------------------

    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Correlate Nmap reconnaissance with PCAP observations"
    )

    correlate_parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    correlate_parser.add_argument(
        "pcap",
        help="Path to the PCAP or PCAPNG file"
    )

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args.target)

    elif args.command == "analyze-pcap":
        run_pcap_analysis(args.pcap)
        
    elif args.command == "correlate":
        run_correlation(
            args.target,
            args.pcap
        )


if __name__ == "__main__":
    main()