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

# wfuzz/wenum
You can replace wenum commands with wfuzz if necessary.
```
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```




