#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth
import hashlib

#CHAT_ID="-xxxx" --- change with your chat id 
CHAT_ID="-xxxxx"

def create_message(alert_json):
    # Get alert information, use empty string if field didn't exist
    title = alert_json['rule']['description'] if 'description' in alert_json['rule'] else ''
    description = alert_json['full_log'] if 'full_log' in alert_json else ''
    description.replace("\\n", "\n") 
    alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else ''
    group_array = ', '.join(alert_json['rule']['groups']) if 'groups' in alert_json['rule'] else ''
    groups=group_array.replace("_"," ") #replace underscore with space, otherwise it will produce a parsing error message
    rule_id = alert_json['rule']['id'] if 'rule' in alert_json else ''
    agent_name = alert_json['agent']['name'] if 'name' in alert_json['agent'] else ''
    agent_id = alert_json['agent']['id'] if 'id' in alert_json['agent'] else ''
    agent_ip = alert_json['agent']['ip'] if 'ip' in alert_json['agent'] else ''
    src_ip = alert_json['data']['srcip'] if 'srcip' in alert_json['data'] else ''
    
    # Format message with markdown
    msg_content = f'*{title}*\n\n'
    msg_content += f'_{description}_\n\n' if len(description) > 0 else ''
    msg_content += f'*Groups:* {groups}\n' if len(groups) > 0 else ''
    msg_content += f'*Source IP:* {src_ip}\n' if len(src_ip) > 0 else ''
    msg_content += f'*Rule:* {rule_id} (Level {alert_level})\n\n'
    msg_content += f'*Agent:* {agent_name} ({agent_id})\n' if len(agent_name) > 0 else ''
    msg_content += f'*Agent IP:* {agent_ip}' if len(agent_ip) > 0 else ''

    msg_data = {}
    msg_data['chat_id'] = CHAT_ID
    msg_data['text'] = msg_content
    msg_data['parse_mode'] = 'markdown'

    #Debug information  
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f'MSG: {msg_data}\n')

    return json.dumps(msg_data)


alert_file = open(sys.argv[1])
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Send the request
msg_data = create_message(alert_json)
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
response = requests.post(hook_url, headers=headers, data=msg_data)
print("telegram : ",msg_data)

#Debug information
with open('/var/ossec/logs/integrations.log', 'a') as f:
    f.write(f'telegram response: {response}\n')

sys.exit(0)
