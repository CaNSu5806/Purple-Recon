import json
import os
from datetime import datetime


def save_json(data, target, output_type):
    """
    Save PurpleRecon data as a timestamped JSON file.

    The output_type determines whether the file contains scan results,
    security events, risk findings, or future PurpleRecon data types.
    """

    # Create the output directory if it does not already exist.
    os.makedirs("output", exist_ok=True)

    # Generate a timestamp so previous scan results are not overwritten.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Use a fallback value if the target could not be determined.
    target = target or "unknown"

    # Example:
    # scan_127.0.0.1_20260824_220500.json
    filename = f"{output_type}_{target}_{timestamp}.json"

    filepath = os.path.join("output", filename)

    # Store the Python data structure as readable JSON.
    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return filepath

def save_html(html_content, target, output_type="report"):
    """
    Save a generated HTML report inside the output directory.

    Args:
        html_content (str): Generated HTML content.
        target (str): Target IP address or hostname.
        output_type (str): Prefix used for the generated filename.

    Returns:
        str: Path of the saved HTML report.
    """

    # Make sure the output directory exists.
    os.makedirs("output", exist_ok=True)

    # Create a timestamp so previous reports are not overwritten.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Use a fallback value if the target is missing.
    target = target or "unknown"

    # Example:
    # report_127.0.0.1_20260827_220500.html
    # purple_report_127.0.0.1_20260827_220500.html
    filename = f"{output_type}_{target}_{timestamp}.html"

    filepath = os.path.join("output", filename)

    # Save the HTML content using UTF-8 encoding.
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(html_content)

    return filepath