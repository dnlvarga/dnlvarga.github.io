---
layout: default
title: File Upload Attack
permalink: /Web/file_upload/
---

# File Upload Attacks
If the user input and uploaded files are not correctly filtered and validated, attackers may be able to exploit the file upload feature to perform malicious activities, like executing arbitrary commands on the back-end server.<br>
Many kinds of scripts can help us exploit web applications through arbitrary file upload, most commonly a Web Shell script and a Reverse Shell script.
*Note: A web shell has to be written in the same programming language that runs the web server.*
- We can often see the web page extension in the URLs.
- Visit the /index.ext page, where we would swap out ext with various common web extensions, like php, asp, aspx, among others, to see whether any of them exist. We can use a tool like Burp Intruder for fuzzing the file extension using a Web Extensions wordlist. This method may not always be accurate, though, as the web application may not utilize index pages or may utilize more than one web extension.
- Use tools like the Wappalyzer browser extension.
