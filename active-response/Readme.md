## Important
### Quarantine.sh
* `quarantine.sh` only works with `custom-misp.py` and MISP rules within this repository. This script quarantine file with IoC, found on MISP DB.
* Make quarantine directory on agent side
  ```
  mkdir /tmp/quarantined
  ```
* Insert these blocks on `/var/ossec/etc/ossec.conf` on server side to invoke active-response command
  ```
    <command>
      <name>quarantine</name>
      <executable>quarantine.sh</executable>
      <timeout_allowed>no</timeout_allowed>
    </command>
  
    <active-response>
      <disabled>no</disabled>
      <command>quarantine</command>
      <location>local</location>
      <rules_id>100623</rules_id>
    </active-response>
  ```
* Create decoder for new active response log in `/var/ossec/etc/decoders/local_decoder.xml`
  ```
    <decoder name="ar_log_json_child">
      <parent>ar_log_json</parent>
      <regex offset="after_parent">(\S+) \S+ \S+ (\S+). \S+ \S+ \S+</regex>
      <order>file_path,quarantined_path</order>
    </decoder>

  ```
* Create rules for active response log in `/var/ossec/etc/decoders/local_rules.xml`
  ```
  <group name="ossec,">
    <rule id="900651" level="10">
      <if_sid>650</if_sid>
      <field name="file_path">\.+</field>
      <match>Successfully</match>
      <description>Malware $(file_path) quarantined</description>
      <group>active_response,misp</group>
    </rule>
  </group>

  ```
* Restart wazuh-manager
