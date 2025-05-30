#!/var/ossec/framework/python/bin/python3
# custom-wazuh_iris.py
# Custom Wazuh integration script to send alerts to DFIR-IRIS

import sys
import json
import requests
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='/var/ossec/logs/integrations.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Function to create a formatted string from alert details
def format_alert_details(alert_json):
    rule = alert_json.get("rule", {})
    agent = alert_json.get("agent", {})
    location = alert_json.get("location", {})
    # Extracting MITRE information from the nested 'rule' structure
    mitre = rule.get("mitre", {})
    mitre_ids = ', '.join(mitre.get("id", ["N/A"]))
    mitre_tactics = ', '.join(mitre.get("tactic", ["N/A"]))
    mitre_techniques = ', '.join(mitre.get("technique", ["N/A"]))

    if location == 'misp':
        details = [
            f"Rule ID: {rule.get('id', 'N/A')}",
            f"Rule Level: {rule.get('level', 'N/A')}",
            f"Rule Description: {rule.get('description', 'N/A')}",
            f"Agent ID: {agent.get('id', 'N/A')}",
            f"Agent Name: {agent.get('name', 'N/A')}",
            f"File Path: {alert_json.get('data', {}).get('misp', {}).get('file_path', 'N/A')}",
            f"MISP value: {alert_json.get('data', {}).get('misp', {}).get('value', 'N/A')}",
            f"MISP Category: {alert_json.get('data', {}).get('misp', {}).get('category', 'N/A')}",
            f"Location: {alert_json.get('location', 'N/A')}",
        ]
    else:
        details = [
        f"Rule ID: {rule.get('id', 'N/A')}",
        f"Rule Level: {rule.get('level', 'N/A')}",
        f"Rule Description: {rule.get('description', 'N/A')}",
        f"Agent ID: {agent.get('id', 'N/A')}",
        f"Agent Name: {agent.get('name', 'N/A')}",
        f"MITRE IDs: {mitre_ids}",
        f"MITRE Tactics: {mitre_tactics}",
        f"MITRE Techniques: {mitre_techniques}",
        f"Location: {alert_json.get('location', 'N/A')}",
        f"Full Log: {alert_json.get('full_log', 'N/A')}"
    ]
    return '\n'.join(details)

def main():
    # Read parameters when integration is run
    if len(sys.argv) < 4:
        logging.error("Insufficient arguments provided. Exiting.")
        sys.exit(1)
    
    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    # Read the alert file
    try:
        with open(alert_file) as f:
            alert_json = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read alert file: {e}")
        sys.exit(1)

    # Prepare alert details
    alert_details = format_alert_details(alert_json)

    # Convert Wazuh rule levels(0-15) -> IRIS severity(1-6)
    alert_level = alert_json.get("rule", {}).get("level", 0)
    if alert_level < 5:
        severity = 2
    elif alert_level >= 5 and alert_level < 7:
        severity = 3
    elif alert_level >= 7 and alert_level < 10:
        severity = 4
    elif alert_level >= 10 and alert_level < 13:
        severity = 5
    elif alert_level >= 13:
        severity = 6
    else:
        severity = 1

    # Generate request
    payload = json.dumps({
        "alert_title": alert_json.get("rule", {}).get("description", "No Description"),
        "alert_description": alert_details,
        "alert_source": "Wazuh",
        "alert_source_ref": alert_json.get("id", "Unknown ID"),
        "alert_source_link": "https://<IP ADDRESS>/app/wz-home",  # Replace with actual Wazuh dashboard IP address
        "alert_severity_id": severity,
        "alert_status_id": 2,  # 'New' status
        "alert_source_event_time": alert_json.get("timestamp", "Unknown Timestamp"),
        "alert_note": "",
        "alert_tags": f"wazuh,{alert_json.get('agent', {}).get('name', 'N/A')}",
        "alert_customer_id": 1,  # '1' for default 'IrisInitialClient'
        "alert_source_content": alert_json  # raw log
    })

    # Send request to IRIS
    try:
        response = requests.post(hook_url, data=payload, headers={"Authorization": "Bearer " + api_key, "content-type": "application/json"}, verify=False)
        if response.status_code in [200, 201, 202, 204]:
            logging.info(f"Sent alert to IRIS. Response status code: {response.status_code}")
        else:
            logging.error(f"Failed to send alert to IRIS. Response status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Failed to send alert to IRIS: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()