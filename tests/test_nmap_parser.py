from purple_recon.parsers.nmap_parser import parse_nmap_xml


def test_parse_nmap_xml():
    """
    Verify that Nmap XML is correctly converted into
    PurpleRecon's structured scan format.
    """

    # Fake Nmap XML lets us test the parser
    # without performing a real network scan.
    sample_xml = """
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="127.0.0.1" addrtype="ipv4"/>

            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service
                        name="ssh"
                        product="OpenSSH"
                        version="9.0"
                    />
                </port>
            </ports>
        </host>
    </nmaprun>
    """

    result = parse_nmap_xml(sample_xml)

    # Verify host-level information.
    assert result["target"] == "127.0.0.1"
    assert result["status"] == "up"

    # Verify that exactly one port was parsed.
    assert len(result["ports"]) == 1

    # Verify the parsed service information.
    port = result["ports"][0]

    assert port["port"] == 22
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"
    assert port["service"] == "ssh"
    assert port["product"] == "OpenSSH"
    assert port["version"] == "9.0"