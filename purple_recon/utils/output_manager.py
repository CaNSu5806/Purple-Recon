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