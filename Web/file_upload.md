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

## Client-Side Validation
Many web applications only rely on front-end JavaScript code to validate the selected file format. We can easily bypass it by directly interacting with the server or by modifying the front-end code. <br>
- If the web application sends a standard HTTP upload request to an endpoint, we can modify the request. Maybe we have to change the "filename" and the file content.
- We can also press [CTRL+SHIFT+C] to toggle the browser's Page Inspector, and then click on the critical area, which is where we trigger the file selector for the upload form. To get the details of functions, we can go to the browser's Console by pressing [CTRL+SHIFT+K], and then we can type the function's name to get its details.
  *Note: The modification we made to the source code is temporary and will not persist through page refreshes, as we are only changing it on the client-side.*

## Blocklist Filters
There are many lists of extensions we can utilize in a fuzzing scan. PayloadsAllTheThings provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use SecLists list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).
### Burp
- Select the desired request in history and send to Intruder.
- From the Positions tab, we can Clear any automatically set positions, and then select the extension in the filename and click the 'Add' button.
- Load the extension list in the Payloads tab under Payload Options. We should un-tick the URL Encoding option to avoid encoding the (.) before the file extension.
- Start Attack.
- We can sort the results by Length to find the interesting ones.
- If we identified a promising extension, we can send it to repeater and modify the request as needed.

*Note: to trigger the uploaded file, we have to determine, where was it uploaded. Sometimes it is enough to upload a file and click on it after pressing [CTRL+SHIFT+C] and see the location in Page Inspector.*

