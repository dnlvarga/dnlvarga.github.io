---
layout: default
title: Service scan
permalink: /service_scan/
---
# Nmap
Tips:
- Once you confirmed that the host is alive, you can add the -Pn flag. If something is filtering ICMP echo requests, you can still get info in that way.
- Check services on all ports. You can increase the speed if you do an initial basic scan on all ports, and do the more aggressive scan on the found ports.
```
ports=$(nmap -p- -T4 --min-rate=1000 -Pn $ip | grep ^[0-9] | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
```
```
nmap -T4 -A -v $ip -oA tcp_scan
```

# Smbclient
`smbclient -N -L \\\\$ip` <br>
`smbclient -N -L \\\\$ip\\users` <br>
`smbclient -U bob \\\\$ip\\users` <br>