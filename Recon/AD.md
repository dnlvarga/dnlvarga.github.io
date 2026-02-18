---
layout: default
title: Web
permalink: /Recon/AD/
---

## Check Anonymous Binds
```
ldapsearch -x -H ldap://$ip:389 -b "dc=$domain, dc=$tld"
```
