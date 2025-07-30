---
layout: default
title: Bypassing Authentication
permalink: /Web/bypass_auth/
---

We will mainly focus on knowledge-based authentication.

# User Enumeration
- Web applications could reveal whether a username exists or not by showing different error messages for the two cases or a chat application might show other users by username to chat with.
- A good starting point is the wordlist collection [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames).
```
ffuf -w /path/to/xato-net-10-million-usernames.txt -u http://$ip/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"
```
- Side-channel attacks do not directly target the web application's response but rather extra information that can be obtained or inferred from the response, e.g. the time it takes for the web application's response to reach us.
