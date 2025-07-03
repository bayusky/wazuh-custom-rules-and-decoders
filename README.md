## Quick Install

You can install the Wazuh Agent by running the following command:

```sh
curl -sSL https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/refs/heads/main/install-agent.sh | sh
```

**Note:**  
For security, always review scripts before running them directly from the internet.

# Wazuh Custom Decoders and Rules
This project contains custom decoders and rules for Wazuh, created by me. Some rules are based on SOC Fortress rules, and some are my own decoders and rules.

### How to use
* Put rules and decoder files under `/var/ossec/etc/rules` and `/var/ossec/etc/decoders`. 
* Put under `/var/ossec/integrations` for integrations script
* Put under `/var/ossec/active-response/bin/` on agent side for active response script.

### Disclaimer 
Feel free to use it, you can redistribute it and/or modify it under the terms of GPLv2. 
Cybersecurity is hard, so let's work together.

### Updates
I will update rules and decoders if the projects I work on require them.

If you find my repository useful, I'm gladly accept a cup of coffee at [ko-fi](https://ko-fi.com/bayusky) or [trakteer](teer.id/bayuskylabs)
