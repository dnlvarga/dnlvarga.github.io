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

Sometimes it is enough to leave the first few bytes of the uploaded file in a valid request and put our script after that to bypass the validation.

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

### XEE
With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server.
- The following example can be used for an SVG image that leaks the content of (/etc/passwd):
  ```
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <svg>&xxe;</svg>
  ```
  Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (/etc/passwd) printed on the page or shown in the page source. It also allows us to read the web application's source files, which is significant. Access to the source code will enable us to find more vulnerabilities to exploit within the web application through Whitebox Penetration Testing. For File Upload exploitation, it may allow us to locate the upload directory, identify allowed extensions, or find the file naming scheme, which may become handy for further exploitation.
  To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:
  ```
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
  <svg>&xxe;</svg>
  ```
  Once the SVG image is displayed, we should get the base64 encoded content of index.php, which we can decode to read the source code.

Using XML data is not unique to SVG images, as it is also utilized by many types of documents, like PDF, Word Documents, PowerPoint Documents, among many others. 
We may utilize the XXE vulnerability to enumerate the internally available services or even call private APIs to perform private actions (type of SSRF attack).

### DoS
- We can use the previous XXE payloads to achieve DoS attacks.
- We can utilize a Decompression Bomb with file types that use data compression, like ZIP archives. If a web application automatically unzips a ZIP archive, it is possible to upload a malicious archive containing nested ZIP archives within it, which can eventually lead to many Petabytes of data, resulting in a crash on the back-end server.
- Another possible DoS attack is a Pixel Flood attack with some image files that utilize image compression, like JPG or PNG. We can create any JPG image file with any image size (e.g. 500x500), and then manually modify its compression data to say it has a size of (0xffff x 0xffff), which results in an image with a perceived size of 4 Gigapixels. When the web application attempts to display the image, it will attempt to allocate all of its memory to this image, resulting in a crash on the back-end server.
-  One way is uploading an overly large file, as some upload forms may not limit the upload file size or check for it before uploading it, which may fill up the server's hard drive and cause it to crash or slow down considerably.
-  If the upload function is vulnerable to directory traversal, we may also attempt uploading files to a different directory (e.g. ../../../etc/passwd), which may also cause the server to crash.

## Injections in File Name
- We can try injecting a command in the file name, and if the web application uses the file name within an OS command, it may lead to a command injection attack. For example, if we name a file file$(whoami).jpg or file`whoami`.jpg or file.jpg||whoami, and then the web application attempts to move the uploaded file with an OS command (e.g. mv file /tmp), then our file name would inject the whoami command, which would get executed, leading to remote code execution.
- Similarly, we may use an XSS payload in the file name (e.g. <script>alert(window.origin);</script>), which would get executed on the target's machine if the file name is displayed to them. We may also inject an SQL query in the file name (e.g. file';select+sleep(5);--.jpg), which may lead to an SQL injection if the file name is insecurely used in an SQL query.

## Upload Directory Disclosure
- We may not have access to the link of our uploaded file and may not know the uploads directory. In such cases, we may utilize fuzzing to look for the uploads directory or even use other vulnerabilities (e.g., LFI/XXE) to find where the uploaded files are by reading the web applications source code
- We can disclose the uploads directory by forcing error messages, as they often reveal helpful information for further exploitation. One attack we can use to cause such errors is uploading a file with a name that already exists or sending two identical requests simultaneously. We may also try uploading a file with an overly long name (e.g., 5,000 characters). If the web application does not handle this correctly, it may also error out and disclose the upload directory.

## Windows-specific Attacks
- One such attack is using reserved characters, such as (|, <, >, *, or ?), which are usually reserved for special uses like wildcards. If the web application does not properly sanitize these names or wrap them within quotes, they may refer to another file (which may not exist) and cause an error that discloses the upload directory. Similarly, we may use Windows reserved names for the uploaded file name, like (CON, COM1, LPT1, or NUL), which may also cause an error.
- Finally, we may utilize the Windows 8.3 Filename Convention to overwrite existing files or refer to files that do not exist. Older versions of Windows were limited to a short length for file names, so they used a Tilde character (~) to complete the file name. As Windows still supports this convention, we can write a file called (e.g. WEB~1.CON) to overwrite the web.conf file.

*Note: Any automatic processing that occurs to an uploaded file, like encoding a video, compressing a file, or renaming a file, may be exploited if not securely coded.*

Some commonly used libraries may have public exploits for such vulnerabilities, like the AVI upload vulnerability leading to XXE in ffmpeg. 




