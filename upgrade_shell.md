---
layout: default
title: Upgrade shell
permalink: /upgrade_shell/
---

# Upgrading TTY

## Python

```
python -c 'import pty; pty.spawn("/bin/bash")'
```
ctrl+z
```
stty raw -echo
```
```
fg
```
Enter (2x)

## Set Up Terminal Params

Check some variables on your terminal:
```
echo $TERM
```
```
stty size
```

Now we can go back to our victim's shell and set these values:
```
export TERM=xterm-256color
```
```
stty rows 67 columns 318
```
(Use the values you got for the `stty size` command)
