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

## Whitelist Filters
### Double Extensions
- If the .jpg extension is allowed, we can add it in our uploaded file name and still end our filename with another extension (e.g. shell.jpg.php). In some cases we are be able to pass the whitelist test with this technique. Usually comprehensive extension list contains these double extensions.
- Sometimes the file name (shell.php.jpg) pass a whitelist test and it would be able to execute PHP code due to misconfigurations.
### Character Injection
We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script. Examples:

- %20
- %0a
- %00
- %0d0a
- /
- .\
- .
- …
- :

For example, (shell.php%00.jpg) works with PHP servers with version 5.X or earlier, as it causes the PHP web server to end the file name after the (%00), and store it as (shell.php), while still passing the whitelist. The same may be used with web applications hosted on a Windows server by injecting a colon (:) before the allowed file extension (e.g. shell.aspx:.jpg), which should also write the file as (shell.aspx). Similarly, each of the other characters has a use case that may allow us to upload a PHP script while bypassing the type validation test.

### Bash script to generate these extensions
```
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':' ''; do
    for ext in '.php' '.phps' '.phar' '.phtml'; do
        if [ -n "$char" ]; then
            echo "shell$char$ext.jpg" >> wordlist.txt
            echo "shell$ext$char.jpg" >> wordlist.txt
            echo "shell.jpg$char$ext" >> wordlist.txt
            echo "shell.jpg$ext$char" >> wordlist.txt
        else
            echo "shell$ext.jpg" >> wordlist.txt
            echo "shell.jpg$ext" >> wordlist.txt
        fi
    done
done
```
## Type Filters
If the web application is testing the file content for type validation, this can be either in the Content-Type Header or the File Content.
### Content-Type Header
Our browsers automatically set the Content-Type header and this operation is a client-side operation, so we can manipulate it.
We may start by fuzzing the Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) through Burp Intruder, to see which types are allowed.
*Note: A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as POST data), in which case we will need to modify the main Content-Type header.*
### MIME-Type
Multipurpose Internet Mail Extensions (MIME) is an internet standard that determines the type of a file through its general format and bytes structure.
Many other image types have non-printable bytes for their file signatures, while a GIF image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string GIF8 is common between both GIF signatures, it is usually enough to imitate a GIF image.
You can check the MIME Type with the `file` command:
```
file <file_name.extension>
```
So just put the 'GIF8' string before your script and change the content-type header and see what happens.
Similarly, we can attempt other combinations and permutations to try to confuse the web server, and depending on the level of code security, we may be able to bypass various filters.

## Limited File Uploads
If we are dealing with a limited (i.e., non-arbitrary) file upload form, which only allows us to upload specific file types, we may still be able to perform some attacks on the web application.

Certain file types, like SVG, HTML, XML, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files. This is why fuzzing allowed file extensions is an important exercise for any file upload attack. It enables us to explore what attacks may be achievable on the web server.

### XSS
Many file types may allow us to introduce a Stored XSS vulnerability to the web application by uploading maliciously crafted versions of them.

- The most basic example is when a web application allows us to upload HTML files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page.
- Another example of XSS attacks is web applications that display an image's metadata after its upload. For such web applications, we can include an XSS payload in one of the Metadata parameters that accept raw text, like the Comment or Artist parameters, as follows:
  ```
  exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' image.jpg
  ```
- Finally, XSS attacks can also be carried with SVG images, along with several other attacks. Scalable Vector Graphics (SVG) images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload. For example, we can write the following to image.svg:
  ```
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
  </svg>
  ```
  Once we upload the image to the web application, the XSS payload will be triggered whenever the image is displayed.

