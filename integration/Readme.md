## Important
### Integration with MISP
* Copy `custom-misp*` file to `/var/ossec/integration`
* Fix permission
```
chown root:wazuh /var/ossec/integrations/custom-misp*
chmod 750 /var/ossec/integrations/custom-misp*
```
* Add this block to `/var/ossec/etc/ossec.conf`
```
  <integration>
    <name>custom-misp</name>
    <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck,recon,attack,web_scan</group>
    <alert_format>json</alert_format>
  </integration>
```
* You can change `<group>` into `<rule_id>` or `<level>`
### Integration with Telegram
* Copy `custom-telegram*` file to `/var/ossec/integration`
* Need your group Chat ID, put into cutom-telegram.py
* Fix permission
```
chown root:wazuh /var/ossec/integrations/custom-telegram*
chmod 750 /var/ossec/integrations/custom-telegram*
```
* Add this block to `/var/ossec/etc/ossec.conf`
```
  <!-- Telegram Integration -->
    <integration>
        <name>custom-telegram</name>
        <rule_id>31105</rule_id>
        <hook_url>https://api.telegram.org/bot<your_code>:<your_api_key>/sendMessage</hook_url>
        <alert_format>json</alert_format>
    </integration>
```
* You need to get API key to your Telegram bot
* You can change `<rule_id>` into `<group>` or `<level>`
### Integration with The Hive
* Copy `custom-thehive` and `custom-thehive.py` to `/var/ossec/integration`
* Fix permission
  ```
  chown root:wazuh /var/ossec/etc/integration/custom-thehive*
  chmod 750 /var/ossec/etc/integration/custom-thehive*
  ```
* Add integration block to `/var/ossec/etc/ossec.conf`
  ```
  <!-- TheHive Integration -->
  <integration>
    <name>custom-thehive</name>
    <hook_url>http://TheHive_Server_IP:9000</hook_url>
    <api_key>API-KEY</api_key>
    <alert_format>json</alert_format>
  </integration>
  ```
