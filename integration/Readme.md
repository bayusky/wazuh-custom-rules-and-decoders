## Important
### Custom-misp
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
### Custom-telegram
* Copy `custom-telegram*` file to `/var/ossec/integration`
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
