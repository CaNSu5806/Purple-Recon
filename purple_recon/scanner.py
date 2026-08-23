import subprocess


def run_nmap(target):
    """
    Runs an Nmap service/version scan against the given target.

    Nmap output is returned as XML so that it can be parsed reliably
    by the parser module instead of processing human-readable output.
    """

    print(f"[*] Target: {target}")
    print("[*] Starting Nmap scan...\n")

    # -sV: Detect services and their versions.
    # -oX -: Produce XML output and write it to stdout instead of a file.
    command = [
        "nmap",
        "-sV",
        "-oX",
        "-",
        target
    ]

    try:
        # capture_output allows PurpleRecon to process Nmap's output
        # instead of letting Nmap print directly to the terminal.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout

    except FileNotFoundError:
        # Raised when Nmap is not installed or cannot be found in PATH.
        print("[!] Nmap could not be found.")
        return None

    except subprocess.CalledProcessError as error:
        # Raised when Nmap executes but returns a non-zero exit code.
        print("[!] Nmap scan failed.")
        print(error.stderr)
        return None