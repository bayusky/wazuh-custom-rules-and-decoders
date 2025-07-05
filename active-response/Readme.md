## Important
### quarantine-malware.sh and quarantine-webshell.sh
* `quarantine-malware.sh` only works with `custom-misp.py` and MISP rules within this repository. This script quarantine file with IoC, found on MISP DB.
* Install jq package for Debian-based OS so OS can read json file from alerts.
  ```
  sudo apt install jq
  ```
* Make quarantine directory on agent side
  ```
  mkdir /tmp/quarantined
  ```
* Insert these blocks on `/var/ossec/etc/ossec.conf` on server side to invoke active-response command
  ```
    <!-- For malware based on MISP-->
    <!-- For Linux agent -->
    <command>
      <name>quarantine-malware</name>
      <executable>quarantine-malware.sh</executable>
      <timeout_allowed>no</timeout_allowed>
    </command>

    <!-- For Windows agent -->
    <command>
      <name>remove-malware</name>
      <executable>remove-malware.exe</executable>
      <timeout_allowed>no</timeout_allowed>
    </command>
  
    <!-- For Linux agent -->
    <active-response>
      <disabled>no</disabled>
      <command>quarantine-malware</command>
      <location>local</location>
      <rules_id>100623</rules_id>
    </active-response>

    <!-- For Windows agent -->
    <active-response>
      <disabled>no</disabled>
      <command>remove-malware</command>
      <location>local</location>
      <rules_id>100623</rules_id>
    </active-response>
    

    <!-- For webshell -->
    <command>
      <name>quarantine-webshell</name>
      <executable>quarantine-webshell.sh</executable>
      <timeout_allowed>no</timeout_allowed>
    </command>

    <active-response>
      <disabled>no</disabled>
      <command>quarantine-webshell</command>
      <location>local</location>
      <rules_id>500500,500501</rules_id>
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
    <!-- Quarantine Malware rules -->
    <group name="ossec,">
    <rule id="900651" level="10">
      <if_sid>650</if_sid>
      <field name="file_path">\.+</field>
      <match>Successfully</match>
      <description>Malware $(file_path) quarantined</description>
      <group>active_response,misp</group>
    </rule>
  </group>
  
  <!-- Remove Malware rules -->
  <group name="ossec,">
    <rule id="900657" level="10">
      <if_sid>657</if_sid>
      <field name="parameters.alert.data.misp.file_path">\.+</field>
      <match>Successfully</match>
      <description>Malware at $(parameters.alert.data.misp.file_path) removed</description>
      <group>active_response,misp</group>
    </rule>
  </group>

  <!-- For Webshell -->
  <!--Rules for AR logs-->
  <group name="ossec">
    <rule id="500092" level="10">
      <if_sid>650</if_sid>
      <match>Successfully quarantine webshell</match>
      <description>Quarantine webshell located at $(file_path)</description>
      <group>active_response,webshell</group>
    </rule>

    <rule id="100093" level="12">
      <if_sid>650</if_sid>
      <match>Failed quarantine webshell</match>
      <description>Error removing webshell located at $(file_path)</description>
      <group>active_response,webshell</group>
    </rule>
  </group>
  

  ```
* Restart wazuh-manager
