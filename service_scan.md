---
layout: default
title: Service scan
permalink: /service_scan/
---
# Nmap
## TCP Scan
Tips:
- Once you confirmed that the host is alive, you can add the -Pn flag. If something is filtering ICMP echo requests, you can still get info in that way.
- Check services on all ports. You can increase the speed if you do an initial basic scan on all ports, and do the more aggressive scan on the found ports.

```
ports=$(nmap -p- -T4 --min-rate=1000 -Pn $ip | grep ^[0-9] | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
```
```
nmap -T4 -A -v -p$ports $ip -oA tcp_scan_$ip
```

## UDP Scan
Tips:
- UDP scans takes forever, so doing scan on a full port range is not recommended

```
nmap -sU -T4 --top-ports 100 -Pn $ip -oA udp_top100_$ip
```



# Smbclient
```
smbclient -N -L \\\\$ip
```

```
smbclient -N -L \\\\$ip\\users
```

```
smbclient -U bob \\\\$ip\\users
```