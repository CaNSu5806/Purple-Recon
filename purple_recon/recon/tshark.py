import subprocess
from pathlib import Path


def analyze_pcap(pcap_path):
    """
    Read a PCAP file with TShark and extract network fields
    required by PurpleRecon's defensive analysis modules.

    Args:
        pcap_path (str): Path to the PCAP/PCAPNG file.

    Returns:
        str | None: Raw tab-separated TShark output.
    """

    # Convert the supplied path into a Path object so that
    # we can validate the capture file before starting TShark.
    capture_file = Path(pcap_path)

    if not capture_file.is_file():
        print(f"[!] Capture file not found: {pcap_path}")
        return None

    print(f"[*] Analyzing PCAP: {capture_file}")

    # Ask TShark to read an existing capture instead of
    # capturing live network traffic.
    command = [
        "tshark",
        "-r", str(capture_file),

        # Produce field-based output instead of the normal
        # human-readable packet summary.
        "-T", "fields",

        # Use tabs between fields. This makes the output
        # easier for our parser to process later.
        "-E", "separator=\t",

        # Basic packet metadata.
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",

        # TCP information needed for later scan analysis.
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout

    except FileNotFoundError:
        print("[!] TShark could not be found in PATH.")
        return None

    except subprocess.CalledProcessError as error:
        print("[!] TShark analysis failed.")
        print(error.stderr)
        return None