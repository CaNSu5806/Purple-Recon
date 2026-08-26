import yaml


def load_config(config_path="configs/config.yaml"):
    """
    Load PurpleRecon configuration from a YAML file.

    Args:
        config_path (str): Path to the YAML configuration file.

    Returns:
        dict: Parsed configuration values.
    """

    # Open the configuration file using UTF-8 encoding.
    with open(config_path, "r", encoding="utf-8") as file:

        # safe_load converts YAML into Python dictionaries
        # without allowing arbitrary Python object execution.
        config = yaml.safe_load(file)

    return config