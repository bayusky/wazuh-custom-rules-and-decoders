For detecting webshell network connection, put this block to `/var/ossec/etc/ossec.conf` in wazuh-agent
```
  <localfile>  
    <log_format>full_command</log_format>
    <command>ss -nputw | egrep '"sh"|"bash"|"csh"|"ksh"|"zsh"' | awk '{ print $5 "|" $6 }'</command>
    <alias>webshell connections</alias>
    <frequency>120</frequency>
  </localfile>
```
