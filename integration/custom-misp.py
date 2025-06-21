#!/usr/bin/env python
## MISP API Integration (Refactored v2)
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re

# --- Input gathering (do not touch) ---
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->misp:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
false = False
# Read configuration parameters
alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()
alert_output = {}
misp_base_url = "<https://MISP_URL/attributes/restSearch/>"
misp_api_auth_key = "<AUTH_KEY>"
misp_apicall_headers = {"Content-Type":"application/json", "Authorization":f"{misp_api_auth_key}", "Accept":"application/json"}

# --- End input gathering ---

# Helper: MISP search and alert output

def misp_search_and_alert(search_value, alert_output, alert, extra_fields=None, file_path=None):
    misp_search_url = ''.join([misp_base_url, f"value:{search_value}"])
    print(misp_search_url)
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=false)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert.get("agent"))
        return False
    misp_api_response = misp_api_response.json()
    if (
        misp_api_response.get("response") and
        "Attribute" in misp_api_response["response"] and
        misp_api_response["response"]["Attribute"]
    ):
        attr = misp_api_response["response"]["Attribute"][0]
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        if file_path:
            alert_output["misp"]["file_path"] = file_path
        alert_output["misp"]["event_id"] = attr.get("event_id", "")
        alert_output["misp"]["category"] = attr.get("category", "")
        alert_output["misp"]["value"] = attr.get("value", "")
        alert_output["misp"]["type"] = attr.get("type", "")
        if extra_fields:
            alert_output.update(extra_fields)
        send_event(alert_output, alert.get("agent"))
        return True
    return False

# --- Main rule logic ---
regex_file_hash = re.compile(r'\w{64}')
event_source = alert["rule"]["groups"][0]
try:
    event_type = alert["rule"]["groups"][2]
except IndexError:
    decoder_name = alert["decoder"]["name"]

if event_source == 'windows':
    # Windows Sysmon
    hashes_path = [
        ('sysmon_event1', lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ('sysmon_event3', lambda: alert["data"]["win"]["eventdata"].get("destinationIp")),
        ('sysmon_event6', lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ('sysmon_event7', lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ('sysmon_event_15', lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ('sysmon_event_22', lambda: alert["data"]["win"]["eventdata"].get("queryName")),
        ('sysmon_event_23', lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ('sysmon_event_24', lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ('sysmon_event_25', lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
    ]
    for etype, getter in hashes_path:
        if event_type == etype:
            try:
                wazuh_event_param = getter()
            except Exception:
                sys.exit()
            # For event3, check if IP is global
            if etype == 'sysmon_event3':
                is_ipv6 = alert["data"]["win"]["eventdata"].get("destinationIsIpv6")
                if is_ipv6 == 'false' and wazuh_event_param and ipaddress.ip_address(wazuh_event_param).is_global:
                    misp_search_and_alert(wazuh_event_param, alert_output, alert)
                sys.exit()
            else:
                misp_search_and_alert(wazuh_event_param, alert_output, alert, extra_fields={"misp": {"source": {"description": alert["rule"].get("description", "")}}})
            break
    else:
        sys.exit()

elif event_source == 'linux':
    if event_type == 'sysmon_event3' and alert["data"]["eventdata"].get("destinationIsIpv6") == 'false':
        try:
            dst_ip = alert["data"]["eventdata"].get("DestinationIp")
            if ipaddress.ip_address(dst_ip).is_global:
                misp_search_and_alert(dst_ip, alert_output, alert)
            else:
                sys.exit()
        except Exception:
            sys.exit()
    elif event_type == 'sysmon_event1' and alert["data"]["eventdata"].get("commandLineCommand") in ['nslookup', 'ping']:
        try:
            wazuh_event_param = alert["data"]["eventdata"].get("commandLineParameter")
            misp_search_and_alert(wazuh_event_param, alert_output, alert)
        except Exception:
            sys.exit()
    else:
        sys.exit()

elif event_source == 'syscheck' and (decoder_name == "syscheck_new_entry" or decoder_name == "syscheck_integrity_changed"):
    md5_after = alert.get("syscheck", {}).get("md5_after")
    sha256_after = alert.get("syscheck", {}).get("sha256_after")
    file_path = alert.get("syscheck", {}).get("path")
    found = False
    if md5_after:
#        if md5_after == "d41d8cd98f00b204e9800998ecf8427e":
#            sys.exit()
        found = misp_search_and_alert(md5_after, alert_output, alert, file_path=file_path)
    if not found and sha256_after:
        misp_search_and_alert(sha256_after, alert_output, alert, file_path=file_path)

elif event_source == 'ossec' and (event_type == "syscheck_entry_added" or event_type == "syscheck_entry_modified"):
    md5_after = alert.get("syscheck", {}).get("md5_after")
    file_path = alert.get("syscheck", {}).get("path")
    if md5_after:
        if md5_after == "d41d8cd98f00b204e9800998ecf8427e":
            sys.exit()
        misp_search_and_alert(md5_after, alert_output, alert, file_path=file_path)

elif event_source == 'web' and (event_type == 'web_scan' or event_type == 'attack'):
    try:
        wazuh_event_param = alert["data"].get("srcip")
        found = misp_search_and_alert(wazuh_event_param, alert_output, alert, extra_fields={"srcip": wazuh_event_param})
        if found:
            with open('/var/ossec/etc/lists/misp_ip_lists.txt', 'a') as file:
                file.write(wazuh_event_param + '\n')
    except Exception:
        sys.exit()

elif event_source == 'syslog' and event_type == 'authentication_failed':
    try:
        wazuh_event_param = alert["data"].get("srcip")
        found = misp_search_and_alert(wazuh_event_param, alert_output, alert, extra_fields={"srcip": wazuh_event_param})
        if found:
            with open('/var/ossec/etc/lists/misp_ip_lists.txt', 'a') as file:
                file.write(wazuh_event_param + '\n')
    except Exception:
        sys.exit()
else:
    sys.exit()
