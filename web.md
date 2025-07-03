---
layout: default
title: Web
permalink: /web/
---

# Gobuster
## Directory/File Enumaration
```
gobuster dir -u http://$ip/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
## DNS Subdomain Enumeration
```
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/namelist.txt
```

# Whatweb
```
whatweb $ip
```

# Banner Grabbing
```
curl -IL http://$domain
```