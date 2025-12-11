import os
import sys
import httpx
import respx
from mock import patch  # or use unittest.mock.patch if available
import pytest

# Ensure the examples directory is in the path.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from crapsecrets.examples import blacklist3r

base_viewstate_page = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head><title>
    Untitled Page
</title></head>
<body>
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="###viewstate###" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    <div>
        <span id="dft">test</span>
    </div>
    </form>
</body>
</html>
"""

vulnerable_viewstate = (
    "o6oVz97xjF/9t1+trA4X4xBFcTnk9bFXqzCNksR5PszHkTScHA/onlBaTUX0tEiHyZX18kIGkuiNoJBmzaGmjEqNsiJuIxrBRjT52D+DEWM7n6d+"
)

non_vulnerable_viewstate = (
    "BADsecrets/9t1+trA4X4xBFcTnk9bFXqzCNksR5PszHkTScHA/onlBaTUX0tEiHyZX18kIGkuiNoJBmzaGmjEqNsiJuIxrBRjT52D+DEWM7n6d+"
)

no_viewstate_page = "<html>Just a website</html>"


def test_examples_blacklist3r_manual(monkeypatch, capsys):
    # Valid Viewstate Unencrypted W/Generator
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "--viewstate",
            "/wEPDwUJODExMDE5NzY5ZGSglOSr1rG6xN5rzh/4C9UEuwa64w==",
            "--generator",
            "EDD8C9AE",
        ],
    )
    blacklist3r.main()
    captured = capsys.readouterr()
    assert "Matching MachineKeys found!" in captured.out
    assert (
        "F5144F1A581A57BA3B60311AF7562A855998F7DD203CD8A71405599B980D8694B5C986C888BE4FC0E6571C2CE600D58CE82B8FA13106B17D77EA4CECDDBBEC1B"
        in captured.out
    )
    assert "ValidationAlgo: [SHA1]" in captured.out

    # Valid Viewstate Encrypted
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "--viewstate",
            "dn/WEP+ogagnOcePgsXoPRe05wss0YIyAZdzFHJuWJejTRbDNDEqes7fBwNY4IqTmT7kTB0o9f8fRSpRXaMcyg==",
        ],
    )
    blacklist3r.main()
    captured = capsys.readouterr()
    assert "Matching MachineKeys found!" in captured.out
    assert (
        "F5144F1A581A57BA3B60311AF7562A855998F7DD203CD8A71405599B980D8694B5C986C888BE4FC0E6571C2CE600D58CE82B8FA13106B17D77EA4CECDDBBEC1B"
        in captured.out
    )
    assert "EncryptionAlgo: [DES]" in captured.out

    # Invalid viewstate is Rejected
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "--viewstate",
            "/wEPDwUJODExMDE5NzY5ZGSglOSr1rG6xN4rzh/4C9UEuwa64w==",
            "--generator",
            "EDD8C9AE",
        ],
    )
    blacklist3r.main()
    captured = capsys.readouterr()
    assert "Matching MachineKeys NOT found" in captured.out

    # Invalid generator is rejected
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "--viewstate",
            "/wEPDwUJODExMDE5NzY5ZGSglOSr1rG6xN5rzh/4C9UEuwa64w==",
            "--generator",
            "^INVALID^",
        ],
    )
    with patch("sys.exit") as exit_mock:
        blacklist3r.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "Generator is not formatted correctly" in captured.err

    # Viewstate doesn't match pattern and is rejected
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "--viewstate",
                "^INVALID^",
                "--generator",
                "EDD8C9AE",
            ],
        )
        blacklist3r.main()
        captured = capsys.readouterr()
        assert "Viewstate is not formatted correctly" in captured.err


def test_examples_blacklist3r_offline(monkeypatch, capsys):
    # Offline mode tests use URL mode.
    with patch("sys.exit") as exit_mock:
        # Invalid URL is rejected
        monkeypatch.setattr("sys.argv", ["python", "--url", "hxxp://notaurl"])
        blacklist3r.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "error: One of --url or --viewstate is required" in captured.err

    with patch("sys.exit") as exit_mock:
        # Both URL and viewstate supplied are mutually exclusive.
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "--url",
                "http://example.com",
                "--viewstate",
                "dn/WEP+ogagnOcePgsXoPRe05wss0YIyAZdzFHJuWJejTRbDNDEqes7fBwNY4IqTmT7kTB0o9f8fRSpRXaMcyg==",
            ],
        )
        blacklist3r.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "error: --viewstate/--generator options and --url option are mutually exclusive" in captured.err

    # Now use respx to simulate HTTP responses.
    with respx.mock:
        respx.get("http://example.com/vulnerableviewstate.aspx").mock(
            return_value=httpx.Response(
                200,
                text=base_viewstate_page.replace("###viewstate###", vulnerable_viewstate),
            )
        )
        respx.get("http://example.com/nonvulnerableviewstate.aspx").mock(
            return_value=httpx.Response(
                200,
                text=base_viewstate_page.replace("###viewstate###", non_vulnerable_viewstate),
            )
        )
        respx.get("http://example.com/noviewstate.aspx").mock(
            return_value=httpx.Response(200, text=no_viewstate_page)
        )
        # Simulate a connection timeout for notreal.com.
        respx.get("http://notreal.com/").mock(side_effect=httpx.ConnectTimeout("Timeout"))
        
        # URL Mode - Valid URL is visited, contains vulnerable viewstate
        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/vulnerableviewstate.aspx"])
        blacklist3r.main()
        captured = capsys.readouterr()
        assert "Matching MachineKeys found!" in captured.out
        assert (
            "F4F0AC3A8889DFBB6FC9D24275A8F0E523C1FB1A2F3FA0C3F3B36320A80670E1D62D15A16A335F0CB14F8AECE7002A5BD8A980F677EA82666B49167947F0A669"
            in captured.out
        )
        assert "EncryptionAlgo: [AES]" in captured.out

        # URL Mode - Valid URL is visited, contains non-vulnerable viewstate
        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/nonvulnerableviewstate.aspx"])
        blacklist3r.main()
        captured2 = capsys.readouterr()
        assert "Matching MachineKeys NOT found" in captured2.out

        # URL Mode - Valid URL is visited, but does not contain viewstate
        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/noviewstate.aspx"])
        blacklist3r.main()
        captured2 = capsys.readouterr()
        assert "Did not find viewstate in response from URL" in captured2.out

        # URL Mode - Valid URL that is not responding (timeout)
        monkeypatch.setattr("sys.argv", ["python", "--url", "http://notreal.com/"])
        blacklist3r.main()
        captured2 = capsys.readouterr()
        assert "Error connecting to URL" in captured2.out


# To run these tests, use a test runner such as pytest.
