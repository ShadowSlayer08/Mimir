"""Device-class profiling from service mix + OS family."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from device_profile import classify  # noqa: E402
from evidence import _blank_host  # noqa: E402


def _host(*svcs, os_name=""):
    h = _blank_host()
    if os_name:
        h["os"] = [{"name": os_name, "family": os_name, "accuracy": "95", "type": ""}]
    for i, n in enumerate(svcs):
        h["ports"].append({"port": 1000 + i, "protocol": "tcp", "state": "open", "reason": "",
                           "service": {"name": n, "product": "", "version": "", "extrainfo": "",
                                       "tunnel": "", "ostype": "", "cpe": []},
                           "scripts": {}, "ssl_enum": None, "least_strength": None, "cert": None})
    return h


def test_ot_device():
    assert classify(_host("modbus", "s7"))[0] == "ICS/OT device"
    assert classify(_host("opcua"))[0] == "ICS/OT device"


def test_camera_and_iot():
    assert classify(_host("rtsp", "http"))[0] == "IP camera / IoT"
    assert classify(_host("upnp", "coap"))[0] == "IoT device"


def test_network_device():
    assert classify(_host("smart-install", "ssh"))[0].startswith("Network device")
    assert classify(_host("snmp", "ssh", os_name="Cisco IOS"))[0].startswith("Network device")


def test_nas():
    assert classify(_host("afp", "iscsi"))[0] == "NAS / storage"
    assert classify(_host("nfs", "microsoft-ds"))[0] == "NAS / storage"


def test_windows_dc_and_host():
    assert classify(_host("kerberos", "ldap", "microsoft-ds"))[0] == "Windows domain controller"
    assert classify(_host("ms-wbt-server", "microsoft-ds"))[0] == "Windows host"


def test_linux_and_generic():
    assert classify(_host("ssh", "http"))[0] == "Linux/Unix host"
    assert classify(_host("echo"))[0] == "Host (generic)"
