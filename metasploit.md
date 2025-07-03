---
layout: default
title: metasploit
permalink: /metasploit/
---

# Metasploit
Run metasploit:
```
msfconsole
```
Search exploit:
```
search <service and version>
```
Select an exploit:
```
use <exploit name or number>
```
Configure the exploit by looking the available configurations and set the values:
```
options
```
```
set <param> <ip>
```
e.g.:
```
set RHOST 10.10.14.149
```
Run the exploit:
```
exploit
```
