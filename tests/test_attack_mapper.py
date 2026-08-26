from purple_recon.analysis.attack_mapper import map_attack_context


def test_attack_mapping():
    """
    Verify that exposed services receive the correct
    MITRE ATT&CK context.
    """

    sample_scan = {
        "target": "127.0.0.1",
        "status": "up",
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh"
            },
            {
                "port": 445,
                "protocol": "tcp",
                "state": "open",
                "service": "microsoft-ds"
            },
            {
                "port": 8080,
                "protocol": "tcp",
                "state": "open",
                "service": "http"
            }
        ]
    }

    mappings = map_attack_context(sample_scan)

    # SSH and SMB should be mapped.
    assert len(mappings) == 2

    ssh = mappings[0]
    smb = mappings[1]

    assert ssh["technique_id"] == "T1021.004"
    assert ssh["service"] == "ssh"

    assert smb["technique_id"] == "T1021.002"
    assert smb["service"] == "microsoft-ds"