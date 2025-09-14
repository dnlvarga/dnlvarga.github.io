---
layout: default
title: LFI Scanning
permalink: /Web/inclusion_scanning/
---

# Automated Scanning
## Fuzzing Parameters
It is important to fuzz for exposed parameters, as they tend not to be as secure as public ones.
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```
Once we identify an exposed parameter that isn't linked to any forms we tested, we can perform all of the LFI tests.
