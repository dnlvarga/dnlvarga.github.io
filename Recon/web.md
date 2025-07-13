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
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$sub.$domain:$port/FUZZ -ic -t 20
```
-ic : Ignore wordlist comments.
-t : Number of concurrent threads. (default: 40)
### Recursive Scanning
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$ip:$port/FUZZ -recursion -recursion-depth 1 -e .php -v
```
- It is always advised to specify a depth to our recursive scan as some websites may have a big tree of sub-directories and it will take a very long time to scan them all.
- When using recursion in ffuf, we can specify our extension with -e .php
- We will also add the flag -v to output the full URLs. Otherwise, it may be difficult to tell which .php file lies under which directory.

## Page Fuzzing
Maybe we found the /blog directory, but it returns an empty page. The directory may contains hidden pages.
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://$ip:$port/blog/indexFUZZ
```
If we get hit, e.g. `.php` gives us response with code 200, we can continue with:
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$ip:$port/blog/FUZZ.php
```
*Note: We can always use two wordlists and have a unique keyword for each, and then do FUZZ_1.FUZZ_2 to fuzz for both.*

## DNS Subdomain Enumeration
```
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/namelist.txt
```
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.$domain -ic -fs 230
```
-ic : Ignore wordlist comments.
-fs : Filter HTTP response size. Comma separated list of sizes and ranges.

*Note: If there is no hit, this only means that there are no public DNS records for sub-domains under the domain. When it came to fuzzing sub-domains that do not have a public DNS record or sub-domains under websites that are not public, we should do vhost fuzzing*

After you found subdomains, you can add them to your local dns:
```
echo "$ip $subdomain.$domain" | sudo tee -a /etc/hosts
```

*Note: You can always repeat the file enumeration on a new found subdomain.*

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

### Search Engine Discovery
#### Search Operators
The exact syntax may vary slightly between search engines.
Some examples:
<table>
  <thead>
    <tr>
      <th>Operator</th>
      <th>Description</th>
      <th>Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>site:</code></td>
      <td>Limits results to a specific site or domain.</td>
      <td><code>site:example.com</code></td>
    </tr>
    <tr>
      <td><code>inurl:</code></td>
      <td>Finds pages with a term in the URL.</td>
      <td><code>inurl:login</code></td>
    </tr>
    <tr>
      <td><code>filetype:</code></td>
      <td>Searches for specific file types.</td>
      <td><code>filetype:pdf</code></td>
    </tr>
    <tr>
      <td><code>intitle:</code></td>
      <td>Searches for a term in the title.</td>
      <td><code>intitle:"confidential report"</code></td>
    </tr>
    <tr>
      <td><code>intext:</code>/<code>inbody:</code></td>
      <td>Searches within body text.</td>
      <td><code>intext:"password reset"</code></td>
    </tr>
    <tr>
      <td><code>AND</code></td>
      <td>Requires all terms to be present.</td>
      <td><code>site:example.com AND (inurl:admin OR inurl:login)</code></td>
    </tr>
    <tr>
      <td><code>OR</code></td>
      <td>Includes pages with any listed terms.</td>
      <td><code>"linux" OR "ubuntu" OR "debian"</code></td>
    </tr>
    <tr>
      <td><code>NOT</code></td>
      <td>Excludes results containing a term.</td>
      <td><code>site:bank.com NOT inurl:login</code></td>
    </tr>
    <tr>
      <td><code>*</code> (wildcard)</td>
      <td>Represents any word or character.</td>
      <td><code>site:socialnetwork.com filetype:pdf user* manual</code></td>
    </tr>
    <tr>
      <td><code>..</code> (range)</td>
      <td>Finds results in a numeric range.</td>
      <td><code>site:ecommerce.com "price" 100..500</code></td>
    </tr>
    <tr>
      <td><code>" "</code> (quotes)</td>
      <td>Matches an exact phrase.</td>
      <td><code>"information security policy"</code></td>
    </tr>
    <tr>
      <td><code>-</code> (minus)</td>
      <td>Excludes a term from the results.</td>
      <td><code>site:news.com -inurl:sports</code></td>
    </tr>
  </tbody>
</table>

<!--
| Operator            | Description                                     | Example                                                  |
|---------------------|-------------------------------------------------|----------------------------------------------------------|
| `site:`             | Limits results to a specific site or domain.    | `site:example.com`                                       |
| `inurl:`            | Finds pages with a term in the URL.             | `inurl:login`                                            |
| `filetype:`         | Searches for specific file types.               | `filetype:pdf`                                           |
| `intitle:`          | Searches for a term in the title.               | `intitle:"confidential report"`                          |
| `intext:`/`inbody:` | Searches within body text.                      | `intext:"password reset"`                                |
| `AND`               | Requires all terms to be present.               | `site:example.com AND (inurl:admin OR inurl:login)`      |
| `OR`                | Includes pages with any listed terms.           | `"linux" OR "ubuntu" OR "debian"`                        |
| `NOT`               | Excludes results containing a term.             | `site:bank.com NOT inurl:login`                          |
| `*` (wildcard)      | Represents any word or character.               | `site:socialnetwork.com filetype:pdf user* manual`       |
| `..` (range)        | Finds results in a numeric range.               | `site:ecommerce.com "price" 100..500`                    |
| `"` `" (quotes)     | Matches an exact phrase.                        | `"information security policy"`                          |
| `-` (minus)         | Excludes a term from the results.               | `site:news.com -inurl:sports`                            |
-->
#### Google Dorking
Finding Login Pages:
- site:example.com inurl:login
- site:example.com (inurl:login OR inurl:admin)
  
Identifying Exposed Files:
- site:example.com filetype:pdf
- site:example.com (filetype:xls OR filetype:docx)

Uncovering Configuration Files:
- site:example.com inurl:config.php
- site:example.com (ext:conf OR ext:cnf) (searches for extensions commonly used for configuration files)

Locating Database Backups:
- site:example.com inurl:backup
- site:example.com filetype:sql

More examples on [Google Hacking Database](https://www.exploit-db.com/google-hacking-database).
### Check the robots.txt file
`example.com/robots.txt` in the URL bar of the browser.

### Check well-konwn URIs
A website's critical metadata, including configuration files and information related to its services, protocols, and security mechanisms typically accessible via the /.well-known/ path on a web server.

### Crawling/Spidering
There are several popular web crawlers like Burp Suite Spider, OWASP ZAP or Scrapy
#### Scrapy
```
pip3 install scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://$domain
cat results.json | jq
```
After running ReconSpider.py, the data will be saved in a JSON file, results.json. 

## Virtual Host Enumeration
Discover virtual hosts configured on a single IP that are not resolvable via DNS, but still reachable by sending a crafted Host: header. When it came to fuzzing sub-domains that do not have a public DNS record or sub-domains under websites that are not public, we should do vhost fuzzing.
In many cases, many websites would actually have sub-domains that are not public and will not publish them in public DNS records, and hence if we visit them in a browser, we would fail to connect, as the public DNS would not know their IP. Once again, if we use the sub-domain fuzzing, we would only be able to identify public sub-domains but will not identify any sub-domains that are not public.
This is where we utilize VHosts Fuzzing on an IP we already have. We will run a scan and test for scans on the same IP, and then we will be able to identify both public and non-public sub-domains and VHosts.
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

```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -H 'Host: FUZZ.academy.htb' -fs 900
```
-fs: This flag filters for response size.
We see that all words in the wordlist are returning 200 OK! This is expected, as we are simply changing the header while visiting http://$domain:$port/. So, we know that we will always get 200 OK. However, if the VHost does exist and we send a correct one in the header, we should get a different response size, as in that case, we would be getting the page from that VHosts, which is likely to show a different page. So it is critical to use filtering.

*Note: Once we've found a vhost, we can run the same command on that, to find additional virtual hosts.*

## Parameter Fuzzing
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://$sub.$domain:$port/$dir/$file.$ext?FUZZ=key -fs 986
```
### Parameter Fuzzing - POST
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://$sub.$domain:$port/$dir/$file.$ext -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

*Note: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".*

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

## Web Archives

We can check previous versions of the website at [The Wayback Machine](https://web.archive.org/). This can also reveal valuable information.

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

## Automating Recon

There are reconnaissance frameworks to automate recon.

### FinalRecon
```
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
./finalrecon.py --headers --whois --url http://$domain
```
