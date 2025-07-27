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
```
Hello {{ name }}!
```
It contains a single variable called `name`, which is replaced with a dynamic value during rendering.
For-loop over all elements in the `names` variable (if is like `names=["name", "name2", "name3"]`):
```
{% for name in names %}
Hello {{ name }}!
{% endfor %}
```

## Confirming SSTI
The most effective way is to inject special characters with semantic meaning in template engines and observe the web application's behavior.
Example:
```
${{<%[%'"}}%\.
```

## Identifying the Template Engine
We can utilize slight variations in the behavior of different template engines.
```
${7*7}
├── ✅ a{*comment*}b
│   ├── ✅ Smarty
│   └── ❌ ${"z".join("ab")}
│       ├── ✅ Mako
│       └── ❌ Unknown
└── ❌ {{7*7}}
    ├── ✅ {{7*7}}
    │   ├── ✅ Jinja2
    │   ├── ✅ Twig
    │   └── ❌ Unknown
    └── ❌ Not vulnerable
```




