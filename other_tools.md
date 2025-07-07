---
layout: default
title: Other Tools
permalink: /other_tools/
---

# JSON beautifier

If you receive JSON output, you can make it more readable by piping it to `jq` utility:
```
curl -s http://<SERVER_IP>:<PORT>/api.php/city/london | jq
```
