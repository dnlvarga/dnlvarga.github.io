---
layout: default
title: Proxychains
permalink: /proxychains/
---

One very useful tool in Linux is proxychains, which routes all traffic coming from any command-line tool to any proxy we specify.
Proxychains adds a proxy to any command-line tool and is hence the simplest and easiest method to route web traffic of command-line tools through our web proxies.
To use proxychains, we first have to edit /etc/proxychains.conf, comment out the final line and add the following line at the end of it:
```
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```
We should also enable Quiet Mode to reduce noise by un-commenting quiet_mode. 

## Nmap
We can also proxy nmap throuh web proxy.
```
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC
```

## Metasploit
```
msfconsole

msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080


msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP

RHOST => SERVER_IP


msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT

RPORT => PORT


msf6 auxiliary(scanner/http/robots_txt) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
