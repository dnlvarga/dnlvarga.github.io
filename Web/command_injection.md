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



