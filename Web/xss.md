---
layout: default
title: XSS
permalink: /Web/xss/
---
#XSS
XSS vulnerabilities take advantage of a flaw in user input sanitization to "write" JavaScript code to the page and execute it on the client side.
When a vulnerable web application does not properly sanitize user input, a malicious user can inject extra JavaScript code in an input field (e.g., comment/reply), so once another user views the same page, they unknowingly execute the malicious JavaScript code.
- A basic example of an XSS attack is having the target user unwittingly send their session cookie to the attacker's web server.
- Another example is having the target's browser execute API calls that lead to a malicious action, like changing the user's password to a password of the attacker's choosing.
- There are many other types of XSS attacks, from Bitcoin mining to displaying ads.

As XSS attacks execute JavaScript code within the browser, they are limited to the browser's JS engine (i.e., V8 in Chrome). They cannot execute system-wide JavaScript code to do something like system-level code execution. In modern browsers, they are also limited to the same domain of the vulnerable website. But if you identify a binary vulnerability in a web browser (e.g., a Heap overflow in Chrome), you can utilize an XSS vulnerability to execute a JavaScript exploit on the target's browser, which eventually breaks out of the browser's sandbox and executes code on the user's machine.
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

## Testing Payloads
```
<script>alert(window.origin)</script>
```
*Note: Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of window.origin in the alert box, instead of a static value like 1. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one.*
As some modern browsers may block the `alert()` JavaScript function in specific locations, it may be handy to know a few other basic XSS payloads to verify the existence of XSS. One such XSS payload is `<plaintext>`, which will stop rendering the HTML code that comes after it and display it as plaintext. Another easy-to-spot payload is `<script>print()</script>` that will pop up the browser print dialog, which is unlikely to be blocked by any browsers.
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
There will be no network traffic and We the input parameter in the URL is using a hashtag # for the item we added, which means that the parameter is a client-side parameter that is completely processed on the browser.
To target a user with this DOM XSS vulnerability, we can once again copy the URL from the browser and share it with them, and once they visit it, the JavaScript code should execute. 
