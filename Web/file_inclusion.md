---
layout: default
title: File Inclusion
permalink: /Web/file_inclusion/
---

# Local File Inclusion (LFI)

It is basically loading a file from a specified path. The most common place we usually find LFI within is templating engines.
Some of the functions used by different frameworks only read the content of the specified files, while others also execute the specified files. Furthermore, some of them allow specifying remote URLs, while others only work with files local to the back-end server. <br>
Two common readable files that are available on most back-end servers are `/etc/passwd` on Linux and `C:\Windows\boot.ini` on Windows. We can try to set these paths as a parameter. <br>
- In many occasions, web developers may append or prepend a string to the parameter. We can easily bypass this restriction by traversing directories using relative paths. To do so, we can add `../` before our file name. <br>
- On some occasions, our input may be appended after a different string. For example, it may be used with a prefix to get the full filename. In this case, if we try to traverse the directory with `../../../etc/passwd`, the final string would be `<prefix>_../../../etc/passwd`, which is invalid. We can prefix a `/` before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories. This may not always work, as a directory named `<prefix>_/` may not exist.
- Another very common example is when an extension is appended to the parameter.

## Second-Order Attacks
A web application may allow us to download our avatar through a URL like (/profile/$username/avatar.png). If we craft a malicious LFI username (e.g. ../../../etc/passwd), then it may be possible to change the file being pulled to another local file on the server and grab it instead of our avatar. Or maybe we manage to poison our username during our registration.
<br>
The only variance is that we need to spot a function that pulls a file based on a value we indirectly control and then try to control that value to exploit the vulnerability.
