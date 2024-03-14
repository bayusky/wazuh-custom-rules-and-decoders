## Important
### Quarantine.sh
* `quarantine.sh` only works with `custom-misp.py` and MISP rules within this repository. This script quarantine file with IoC, found on MISP DB.
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
