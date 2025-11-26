## Monitor your web browser using Wazuh
### Windows
Install using one liner in Windows Terminal or PowerShell as Administrator
```
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/main/browser-monitoring/windows-installer.ps1' | iex"
```
Follow logs using this configuration (inside agent or centralized):
```
    <localfile>
      <location>C:\BrowserMonitor\browser_history.log</location>
      <log_format>syslog</log_format>
      <out_format>browser-history: $(log)</out_format>
    </localfile>   
```
### Linux and MacOS
Install using this lines 
```
curl -s https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/main/browser-monitoring/installer-script.sh | bash
```
