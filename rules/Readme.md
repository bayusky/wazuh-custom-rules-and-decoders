## Important
* If you use SOCFortress Advance Rules, you have to change misp and opencti rule id according to this repository to make rule id: 100623 works for malware quarantine active-response.

## For Judol files detection
Put this syscheck configuration on your agent configuration or groups configuration inside syscheck configuration.
```
<directories realtime="yes" check_all="yes" report_changes="yes">/var/www/html</directories>
```
Make sure to change directory path according to your website directories.
