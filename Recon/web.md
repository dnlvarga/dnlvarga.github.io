---
layout: default
title: Web
permalink: /Recon/web/
---

## Directory/File Enumaration
```
gobuster dir -u http://$ip/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$sub.$domain/FUZZ -ic -t 20
```
-ic : Ignore wordlist comments.
-t : Number of concurrent threads. (default: 40)

## DNS Subdomain Enumeration
```
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/namelist.txt
```
```
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host:FUZZ.$domain" -u http://$domain -ic -fs 230
```
-ic : Ignore wordlist comments.
-fs : Filter HTTP response size. Comma separated list of sizes and ranges.

After you found subdomains, you can add them to your local dns:
```
echo "$ip $subdomain.$domain" | sudo tee -a /etc/hosts
```

You can always repeat the file enumeration on a new found subdomain.

# Whatweb
```
whatweb $ip
```

# Banner Grabbing
```
curl -IL http://$domain
```

# Git Dumping

If a `.git` directory is exposed, you can use a tool like [gitdumper](https://github.com/arthaud/git-dumper).
```
python3 git_dumper.py http://dev.$domain gitdump
```
After that you can navigate to the gitdump directory and check the git status:
```
cd gitdump && git status
```
If we see changes have been made, we can view it by restoring the staged changes and see the differences:
```
git restore --staged . && git diff
```

# Check source code

Merely type `ctrl + u` when you are in the browser or put `view-source:` before the URL in the URL bar. This could reveal sensitive data, like test credentials.
