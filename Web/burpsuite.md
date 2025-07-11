---
layout: default
title: BurpSuite
permalink: /Web/burpsuite/
---

# Intercept Request
Intercept and send the request edit it and forward it.
You can also send it to Intruder [CTRL+I]. Then you can edit the request in the Intruder tab [CTRL+SHIFT+I].

# Intercept Response
In Proxy settings search for Intercept response.
Enable Intercept response under Intercept Server Response.

# Automatic Modification
In Proxy settings search for Match and Replace. You can click "Add" and then you can select Request header, Response body or whatever you want. You can do Regex matches.

# Repeating Requests
Select the request in Proxy>HTTP History, which you want to repeat.
Send the request to Repeater [CTRL+R]. Then you can edit the request in the Repeater tab [CTRL+SHIFT+R] and resend it.

# URL Encoding/Decoding
In Repeater we can easily URL encode, just select a text and CTRL+U or right-click on the selected text, then select Convert Selection>URL>URL encode key characters.
