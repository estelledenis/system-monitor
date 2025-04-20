from unittest.mock import patch, MagicMock
import os
import json

@patch('vulnerability_scan.nmap_scan_windows.nmap.PortScanner')
def test_scan_localhost_windows(mock_portscanner_class):
    mock_scanner = MagicMock()
    mock_host = MagicMock()

    mock_host.all_protocols.return_value = ['tcp']
    mock_host.has_tcp.return_value = True
    mock_host = {
        'tcp': {
            3389: {"state": "open"}
        }
    }
    mock_scanner.__getitem__.return_value = mock_host
    mock_portscanner_class.return_value = mock_scanner

    from vulnerability_scan import nmap_scan_windows

    output_path = nmap_scan_windows.scan_localhost()

    assert output_path is not None
    assert os.path.exists(output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "scan_time" in data
    assert "host" in data
    assert "scan" in data  # FIX HERE!

