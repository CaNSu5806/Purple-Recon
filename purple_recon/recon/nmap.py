import subprocess


def run_nmap(target, scanner_config):
    """
    Run an Nmap scan using settings loaded from config.yaml.

    Args:
        target (str): Target IP address or hostname.
        scanner_config (dict): Scanner-related configuration values.

    Returns:
        str | None: Nmap XML output if successful.
    """

    print(f"[*] Target: {target}")
    print("[*] Starting Nmap scan...\n")

    # Start building the Nmap command.
    command = [
        "nmap"
    ]

    # Read configured port range.
    ports = scanner_config.get("ports")

    if ports:
        command.extend([
            "-p",
            str(ports)
        ])

    # Enable service/version detection only when configured.
    if scanner_config.get("version_detection", True):
        command.append("-sV")

    # Return XML directly to Python through stdout.
    command.extend([
        "-oX",
        "-",
        target
    ])

    # Read the subprocess timeout from configuration.
    timeout = scanner_config.get("timeout", 120)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )

        return result.stdout

    except FileNotFoundError:
        print("[!] Nmap could not be found.")
        return None

    except subprocess.TimeoutExpired:
        print(f"[!] Nmap scan timed out after {timeout} seconds.")
        return None

    except subprocess.CalledProcessError as error:
        print("[!] Nmap scan failed.")
        print(error.stderr)
        return None