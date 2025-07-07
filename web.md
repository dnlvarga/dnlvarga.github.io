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
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$sub.$domain/FUZZ -ic -t 20
```
-ic : Ignore wordlist comments.
-t : Number of concurrent threads. (default: 40)

## DNS Subdomain Enumeration
```
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/namelist.txt
```
```
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host:FUZZ.$domain" -u http://$domain -ic -fs 230
```
-ic : Ignore wordlist comments.
-fs : Filter HTTP response size. Comma separated list of sizes and ranges.

After you found subdomains, you can add them to your local dns:
```
echo "$ip $subdomain.$domain" | sudo tee -a /etc/hosts
```

# Whatweb
```
whatweb $ip
```

# Banner Grabbing
```
curl -IL http://$domain
```
