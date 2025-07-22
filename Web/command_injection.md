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
- Using the ($IFS) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use ${IFS} where the spaces should be, the variable should be automatically replaced with a space.
- We can use the Bash Brace Expansion feature, which automatically adds spaces between arguments wrapped between braces, as follows: `{ls,-la}`.

### Bypass Specail Characters
- One technique we can use for replacing characters is through Linux Environment Variables. While ${IFS} is directly replaced with a space, other characters may be used in other environment variables, and we can specify start and length of our string to exactly match the desired character. E.g. `${PATH:0:1}` is probably a `/`, `${LS_COLORS:10:1}` is probably a `;`. Other candidates: `$HOME` or `$PWD`.

*Note: The `printenv` command prints all environment variables in Linux, so you can look which ones may contain useful characters, and then try to reduce the string to that character only.*



