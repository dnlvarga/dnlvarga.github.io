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

