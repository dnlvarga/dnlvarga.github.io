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


