---
layout: default
title: Verb Tempering
permalink: /Web/verb_tempering/
---

# HTTP Verb Tampering
If the web server configurations are not restricted to only accept the HTTP methods required by the web server (e.g. GET/POST), and the web application is not developed to handle other types of HTTP requests (e.g. HEAD, PUT), then some HTTP methods might be accessible without authentication or bypass injection detections. 
We just need to try alternate HTTP methods to see how they are handled by the web server and the web application. 

- If a restricted page uses a GET request, we can send a POST request and see whether the web page allows POST requests (i.e., whether the Authentication covers POST requests). To do so, we can right-click on the intercepted request in Burp and select 'Change Request Method', and it will automatically change the request into a POST request.
- We can also try the HEAD method, which is identical to a GET request but does not return the body in the HTTP response. If this is successful, we may not receive any output, but the function should still get executed.
- To see whether the server accepts HEAD requests, we can send an OPTIONS request to it and see what HTTP methods are accepted: `curl -i -X OPTIONS http://SERVER_IP:PORT/`
