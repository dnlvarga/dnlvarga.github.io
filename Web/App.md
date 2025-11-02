---
layout: default
title: Common Application Attacks
permalink: /Web/App/
---

# Application Discovery & Enumeration

[EyeWitness](https://github.com/RedSiege/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone) are tools to help us quickly inspect all hosts running web applications and take screenshots using raw Nmap XML scan outputs as input.

## Getting Organized

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
