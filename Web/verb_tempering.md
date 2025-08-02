---
layout: default
title: Verb Tempering
permalink: /Web/verb_tempering/
---

# HTTP Verb Tampering
Suppose both the web application and the back-end web server are configured only to accept GET and POST requests. In that case, sending a different request will cause a web server error page to be displayed, which is not a severe vulnerability in itself (it can potentially lead to information disclosure). On the other hand, if the web server configurations are not restricted to only accept the HTTP methods required by the web server (e.g. GET/POST), and the web application is not developed to handle other types of HTTP requests (e.g. HEAD, PUT), then we may be able to exploit this insecure configuration.

- Insecure Configurations: A web server's authentication configuration may be limited to specific HTTP methods, which would leave some HTTP methods accessible without authentication. For example, a system admin may use the following configuration to require authentication on a particular web page:
  ```
  <Limit GET POST>
      Require valid-user
  </Limit>
  ```
- Insecure Coding: This is commonly found in security filters that detect malicious requests. For example, if a security filter was being used to detect injection vulnerabilities and only checked for injections in POST parameters (e.g. `$_POST['parameter']`), it may be possible to bypass it by simply changing the request method to GET.

## Bypassing Basic Authentication

Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application. While many automated vulnerability scanning tools, they usually miss identifying HTTP Tampering vulnerabilities caused by insecure coding. 

- If a restricted page uses a GET request, we can send a POST request and see whether the web page allows POST requests (i.e., whether the Authentication covers POST requests). To do so, we can right-click on the intercepted request in Burp and select 'Change Request Method', and it will automatically change the request into a POST request.
- We can also try the HEAD method, which is identical to a GET request but does not return the body in the HTTP response. If this is successful, we may not receive any output, but the function should still get executed.
- To see whether the server accepts HEAD requests, we can send an OPTIONS request to it and see what HTTP methods are accepted: `curl -i -X OPTIONS http://SERVER_IP:PORT/`
