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

```
dnsenum --enum $domain -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```
-r: This option enables recursive subdomain brute-forcing, meaning that if dnsenum finds a subdomain, it will then try to enumerate subdomains of that subdomain.

### Zone Transfer Enumeration
```
dig axfr @$NS $domain
```
@$NS - The DNS nameserver to query. The @ syntax tells dig to query this specific server. E.g. `@nsztm1.digi.ninja` or `@$ip`. You can query the authoritative name servers for the domain with `dig $domain NS`<br> 
This command instructs dig to request a full zone transfer (axfr) from the DNS server responsible for zonetransfer.me. If the server is misconfigured and allows the transfer, you'll receive a complete list of DNS records for the domain, including all subdomains.

### Certificate Transparency (CT) Logs Recon
```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
`curl -s "https://crt.sh/?q=facebook.com&output=json"`: This command fetches the JSON output from crt.sh for certificates matching the domain facebook.com. <br>
`jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`: This part filters the JSON results, selecting only entries where the name_value field (which contains the domain or subdomain) includes the string "dev". The -r flag tells jq to output raw strings. <br>
`sort -u`: This sorts the results alphabetically and removes duplicates.

### Google it 
`site:example.com` in the search bar.

### Check the robots.txt file
`example.com/robots.txt` in the URL bar of the browser.

## Virtual Host Enumeration
```
gobuster vhost -u http://$domain:$port -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```
```
gobuster vhost -u http://$ip:$port -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain --domain $domain
```
--append-domain: Appends the base domain to each word in the wordlist. <br>
Other useful flags:
-t: To increase the number of threads for faster scanning.
-k: This flag can ignore SSL/TLS certificate errors.
-o: To save the output to a file for later analysis.

## Fingerprinting

Fingerprinting focuses on extracting technical details about the technologies powering a website or web application.

### Banner Grabbing
```
curl -I $domian
```
If it's also trying to redirect to somewhere, grab those banners too.

### Identifying Web Application Firewalls (WAFs)
```
wafw00f $domain
```

### Nikto
Nikto is an open-source web server scanner. Its primary function is vulnerability assessment. Its fingerprinting capabilities provide insights into a website's technology stack.
```
nikto -h $domain -Tuning b
```
-h: This flag specifies the target host. 
-Tuning b: This flag tells Nikto to only run the Software Identification modules.

*Note: You can use Wappalyzer Browser Extension too for fingerprinting.* 

### Whatweb
Uses a database of signatures to identify various web technologies.
```
whatweb $ip
```
```
whatweb $domain
```
Can reveal e.g. OS or the CMS.

## Git Dumping

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

## Check source code

Merely type `ctrl + u` when you are in the browser or put `view-source:` before the URL in the URL bar. This could reveal sensitive data, like test credentials.
