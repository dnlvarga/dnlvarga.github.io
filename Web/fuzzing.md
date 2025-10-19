---
layout: default
title: Fuzzing
permalink: /Web/fuzzing/
---

# Tooling

## Installing Go, Python and PIPX
```sudo apt update```
```sudo apt install -y golang```
```sudo apt install -y python3 python3-pip```
```
sudo apt install pipx
pipx ensurepath
sudo pipx ensurepath --global
```
Checks:
```
go version
python3 --version
```

## Ffuf
```
go install github.com/ffuf/ffuf/v2@latest
```

## Gobuster
```
go install github.com/OJ/gobuster/v3@latest
```

## FeroxBuster
FeroxBuster is a recursive content discovery tool. It's more of a "forced browsing" tool than a fuzzer like ffuf.
```
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin
```

## wfuzz/wenum
You can replace wenum commands with wfuzz if necessary.
```
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

# Directory and File Fuzzing
 Hidden resources may contain sensitive information, backup files, configuration files, or even old, vulnerable application versions.
 Directory and file fuzzing involves systematically probing the web application with a list of potential directory and file names and analyzing the server's responses.

 ## Directory Fuzzing
 
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ
```

 ## File Fuzzing

 ```
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/<dir_name>/FUZZ.html -e .php,.html,.txt,.bak,.js -v
```

# Recursive Fuzzing
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion
```
The `-ic` option ignores commented lines in wordlists during fuzzing.
*Note: Excessive requests can overwhelm the target server.*
Other useful options:
- `-recursion-depth`: maximum depth for recursive exploration.
- `-rate`: the rate at which ffuf sends requests per second.
- `-timeout`: sets the timeout for individual requests, which prevents the fuzzer from hanging on unresponsive targets.
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
```
