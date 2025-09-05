---
layout: default
title: File Inclusion
permalink: /Web/file_disclosure/
---

# File Disclosure

## Local File Inclusion (LFI)

It is basically loading a file from a specified path. The most common place we usually find LFI within is templating engines.
Some of the functions used by different frameworks only read the content of the specified files, while others also execute the specified files. Furthermore, some of them allow specifying remote URLs, while others only work with files local to the back-end server. <br>
Two common readable files that are available on most back-end servers are `/etc/passwd` on Linux and `C:\Windows\boot.ini` on Windows. We can try to set these paths as a parameter. <br>
- In many occasions, web developers may append or prepend a string to the parameter. We can easily bypass this restriction by traversing directories using relative paths. To do so, we can add `../` before our file name. <br>
- On some occasions, our input may be appended after a different string. For example, it may be used with a prefix to get the full filename. In this case, if we try to traverse the directory with `../../../etc/passwd`, the final string would be `<prefix>_../../../etc/passwd`, which is invalid. We can prefix a `/` before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories. This may not always work, as a directory named `<prefix>_/` may not exist.
- Another very common example is when an extension is appended to the parameter.

### Second-Order Attacks
A web application may allow us to download our avatar through a URL like (/profile/$username/avatar.png). If we craft a malicious LFI username (e.g. ../../../etc/passwd), then it may be possible to change the file being pulled to another local file on the server and grab it instead of our avatar. Or maybe we manage to poison our username during our registration.
<br>
The only variance is that we need to spot a function that pulls a file based on a value we indirectly control and then try to control that value to exploit the vulnerability.

## Basic Bypsasses

### Non-Recursive Path Traversal Filters
One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of `../`. However, this filter is very insecure, as it is not recursively removing the `../` substring. For example, if we use `....//` as our payload, then the filter would remove `../` and the output string would be `../`.

### Encoding
Some web filters may prevent input filters that include certain LFI-related characters, like a dot `.` or a slash `/` used for path traversals. However, some of these filters may be bypassed by URL encoding our input. Furthermore, we may also encode the encoded string once again to have a double encoded string, which may also bypass other types of filters.
*Note: For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.*

### Approved Paths
Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality. Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match. To bypass this, we may use path traversal and start our payload with the approved path, and then use ../ to go back to the root directory and read the file we specify.

### Appended Extension
There are a couple of other techniques we may use, but they are obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4. However, it may still be beneficial to mention them, as some web applications may still be running on older servers, and these techniques may be the only bypasses possible.

#### Path Truncation
- In earlier versions of PHP, defined strings have a maximum length of 4096 characters. If a longer string is passed, it will simply be truncated.
- PHP also used to remove trailing slashes and single dots in path names, so if we call (`/etc/passwd/.`) then the `/.` would also be truncated, and PHP would call `/etc/passwd`.
- PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`). Similarly, a current directory shortcut `.` in the middle of the path would also be disregarded (e.g. `/etc/./passwd`). If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path.
  *Note: It is also important to note that we would also need to start the path with a non-existing directory for this technique to work: `?language=non_existing_directory/../../../etc/passwd/./././././ REPEATED ~2048 times]`.*
  Bash script for that: `echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done`
  *Note: if we use this method, we should calculate the full length of the string to ensure only `.php` gets truncated and not our requested file at the end of the string `/etc/passwd`.*

#### Null Bytes
PHP versions before 5.5 were vulnerable to null byte injection, which means that adding a null byte (%00) at the end of the string would terminate the string and not consider anything after it (e.g. `/etc/passwd%00`).
