---
layout: default
title: SSRF
permalink: /Web/ssrf/
---

# Server-Side Request Forgery (SSRF)
This type of vulnerability occurs when an attacker can manipulate a web application into sending unauthorized requests from the server, because the web application fetches additional resources from a remote location based on user-supplied data, such as a URL.<br>
The following URL schemes are commonly used in the exploitation of SSRF vulnerabilities:
- http:// and https://: These URL schemes fetch content via HTTP/S requests. An attacker might use this in the exploitation of SSRF vulnerabilities to bypass WAFs, access restricted endpoints, or access endpoints in the internal network.
- file://: This URL scheme reads a file from the local file system. An attacker might use this in the exploitation of SSRF vulnerabilities to read local files on the web server (LFI).
- gopher://: This protocol can send arbitrary bytes to the specified address. An attacker might use this in the exploitation of SSRF vulnerabilities to send HTTP POST requests with arbitrary payloads or communicate with other services such as SMTP servers or databases.

## Confirming SSRF
- Supply a URL pointing to our system to the web aaplication, while we are listening with e.g. netcat.
- To determine, whether the HTTP response reflects the response, we can point the web application to itself, e.g. `http://127.0.0.1/index.php`.
If we see the HTML code in the response, the SSFR is not blind.

## Enumerating the System
We can do this using a fuzzer like ffuf.
```
seq 1 10000 > ports.txt
```
```
ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```
*Note: First check the error message in case of a closed port to apply the `-fr` regex filter correctly.*
