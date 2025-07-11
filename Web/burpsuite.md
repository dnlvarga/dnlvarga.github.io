---
layout: default
title: BurpSuite
permalink: /Web/burpsuite/
---

# Intercept Request
Intercept and send the request edit it and forward it.

# Intercept Response
In Proxy settings search for Intercept response.
Enable Intercept response under Intercept Server Response.

# Automatic Modification
In Proxy settings search for Match and Replace. You can click "Add" and then you can select Request header, Response body or whatever you want. You can do Regex matches.

# Repeating Requests
Select the request in Proxy>HTTP History, which you want to repeat.
Send the request to Repeater [CTRL+R]. Then you can edit the request in the Repeater tab [CTRL+SHIFT+R] and resend it.

# URL Encoding/Decoding
- In Repeater we can easily URL encode, just select a text and CTRL+U or right-click on the selected text, then select Convert Selection>URL>URL encode key characters (or select another type of encoding).
- There is a Decoder tab in Burp [CTRL+E]. Here we can quickly encode or decode however we want.
- You can also use Burp Inspector which can be found in various places like Burp Proxy or Burp Repeater.

# Web Fuzzing
We can go to the Proxy History, locate our request, then right-click on the request and select Send to Intruder, or use the shortcut [CTRL+I] to send it to Intruder. We can then go to Intruder by clicking on its tab or with the shortcut [CTRL+SHIFT+I], which takes us right to Burp Intruder.
- We can place payload position pointers, which are the points where words from our wordlist will be placed and iterated over. We will need to select a part of the request as the payload position, by either wrapping it with § or by selecting the part and clicking on the Add § button.
- Select an Attack Type.
- Configure the payloads on the Payloads part. E.g. in the Payload Processing part you can skip lines with "Skip if matches regex" option.
- In the Settings, we can also set up a lot of useful things, e.g. with the "Grep - Match" option we can flag specific requestes depending of the response or with the "Grep - Extract" option is useful when the HTTP responses are lengthy and we're only interested in a certain part of the response.
- Start the attack.

  Note that the Community Version is very slow, don't use long wordlists, if you don't want to wait forever.


  > **Note:** We can use ZAP which is not throttled as Brup Community Version. Start it by typing `zaproxy` in the commandline. ZAP Scanner is capable of building site maps using ZAP Spider and performing both passive and active scans to look for various types of vulnerabilities.
