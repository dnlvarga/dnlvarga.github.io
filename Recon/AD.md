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
