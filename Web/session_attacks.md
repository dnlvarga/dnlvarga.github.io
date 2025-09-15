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




