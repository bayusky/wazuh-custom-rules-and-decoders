Copy these file to `/var/ossec/integration`
Fix permission
```
chown root:wazuh /var/ossec/integrations/custom-misp*
chmod 750 /var/ossec/integrations/custom-misp*
```
Add this block to `/var/ossec/etc/ossec.conf`
```
<integration>
	<name>custom-misp</name>
	<group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>
	<alert_format>json</alert_format>
</integration>
```
