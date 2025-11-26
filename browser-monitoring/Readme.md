## Monitor your web browser using Wazuh
Install using one liner in ps1
```
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/main/browser-monitoring/windows-installer.ps1' | iex"
```
