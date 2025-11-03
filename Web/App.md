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



