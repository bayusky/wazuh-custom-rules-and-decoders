#!/usr/bin/env python
## MISP API Integration
#
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

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# print(pwd)
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
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if MISP Alert or Error calling the API
alert_output = {}
# MISP Server Base URL
misp_base_url = "<https://MISP_URL/attributes/restSearch/>"
# MISP Server API AUTH KEY
misp_api_auth_key = "<AUTH_KEY>"
# API - HTTP Headers
misp_apicall_headers = {"Content-Type":"application/json", "Authorization":f"{misp_api_auth_key}", "Accept":"application/json"}
## Extract Sysmon for Windows/Sysmon for Linux and Sysmon Event ID
event_source = alert["rule"]["groups"][0]
try:
	event_type = alert["rule"]["groups"][2]
except IndexError:
	decoder_name = alert["decoder"]["name"]
## Regex Pattern used based on SHA256 lenght (64 characters)
regex_file_hash = re.compile('\w{64}')
if event_source == 'windows':
    if event_type == 'sysmon_event1':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["win"]["eventdata"]["destinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert_output["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'true':
        sys.exit()
    elif event_type == 'sysmon_event6':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event7':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_15':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_22':
        try:
            wazuh_event_param = alert["data"]["win"]["eventdata"]["queryName"]
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_23':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_24':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_25':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    else:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["integration"] = "misp"
            alert_output["misp"]["source"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            alert_output["misp"]["source"]["description"] = alert["rule"]["description"]
            send_event(alert_output, alert["agent"])
elif event_source == 'linux':
    if event_type == 'sysmon_event3' and alert["data"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["eventdata"]["DestinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
            else:
                sys.exit()
        except IndexError:
            sys.exit()
                
    elif event_type == 'sysmon_event1' and alert["data"]["eventdata"]["commandLineCommand"] == 'nslookup':
        try:
            wazuh_event_param = alert["data"]["eventdata"]["commandLineParameter"]
        except IndexError:
            sys.exit()

    elif event_type == 'sysmon_event1' and alert["data"]["eventdata"]["commandLineCommand"] == 'ping':
        try:
            wazuh_event_param = alert["data"]["eventdata"]["commandLineParameter"]
        except IndexError:
            sys.exit()
    else:
        sys.exit()
    
    print(wazuh_event_param)
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
        print(misp_api_response)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
        print(misp_api_response)
        # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
            # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["integration"] = "misp"
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            send_event(alert_output, alert["agent"])
            print(alert_output)

#MISP syscheck, check hash of a file   
elif event_source == 'syscheck' and (decoder_name == "syscheck_new_entry" or decoder_name == "syscheck_integrity_changed"):
    try:
        wazuh_event_param = alert["syscheck"]["md5_after"]
    except IndexError:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=false)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
        print(misp_api_response)
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["integration"] = "misp"
            alert_output["misp"]["file_path"] = alert["syscheck"]["path"]
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
           # print(alert_output)
            send_event(alert_output, alert["agent"])
        else:
            #check sha256 if md5 not found
            wazuh_event_param = alert["syscheck"]["sha256_after"]
            misp_search_value = "value:"f"{wazuh_event_param}"
            misp_search_url = ''.join([misp_base_url, misp_search_value])
            try:
                misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=false)
            except ConnectionError:
                alert_output["misp"] = {}
                alert_output["integration"] = "misp"
                alert_output["misp"]["error"] = 'Connection Error to MISP API'
                send_event(alert_output, alert["agent"])
            else:
                misp_api_response = misp_api_response.json()
                print(misp_api_response)
                # Check if response includes Attributes (IoCs)
                if (misp_api_response["response"]["Attribute"]):
                    # Generate Alert Output from MISP Response
                    alert_output["misp"] = {}
                    alert_output["integration"] = "misp"
                    alert_output["misp"]["file_path"] = alert["syscheck"]["path"]
                    alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                    alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                    alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                    alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                   # print(alert_output)
                    send_event(alert_output, alert["agent"])
elif event_source == 'ossec' and (event_type == "syscheck_entry_added" or event_type == "syscheck_entry_modified"):
    try:
        wazuh_event_param = alert["syscheck"]["md5_after"]
    except IndexError:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=false)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
    #    print(misp_api_response)
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["integration"] = "misp"
            alert_output["misp"]["file_path"] = alert["syscheck"]["path"]
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
           # print(alert_output)
            send_event(alert_output, alert["agent"])

#MISP web attack/scan source IP check
elif event_source == 'web' and (event_type == 'web_scan' or event_type == 'attack'):
    try:
        wazuh_event_param = alert["data"]["srcip"]
    except IndexError:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=false)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
        print("misp web search url : ",misp_search_url)
        print("misp web response IP : ",misp_api_response)
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["integration"] = "misp"
            alert_output["srcip"] = wazuh_event_param
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
           # print(alert_output)
            send_event(alert_output, alert["agent"])
	   # write MISP IP list to a file for future blocklist
            with open('/var/ossec/etc/lists/misp_ip_lists.txt', 'a') as file:
                file.write(wazuh_event_param + '\n')
                print(f"misp : Added srcip {wazuh_event_param} to misp_ip_lists.txt")

#MISP authentication failed
elif event_source == 'syslog' and event_type == 'authentication_failed':
    try:
        wazuh_event_param = alert["data"]["srcip"]
    except IndexError:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=false)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
        print("misp web search url : ",misp_search_url)
        print("misp web response IP : ",misp_api_response)
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["srcip"] = wazuh_event_param
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
           # print(alert_output)
            send_event(alert_output, alert["agent"])
	   # write MISP IP list to a file for future blocklist
            with open('/var/ossec/etc/lists/misp_ip_lists.txt', 'a') as file:
                file.write(wazuh_event_param + '\n')
                print(f"misp : Added srcip {wazuh_event_param} to misp_ip_lists.txt")
else:
    sys.exit()

