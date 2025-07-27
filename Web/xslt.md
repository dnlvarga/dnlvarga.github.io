---
layout: default
title: XSLT
permalink: /Web/xslt/
---

# XSLT Server-Side Injection
XSLT (Extensible Stylesheet Language Transformations) server-side injection is a vulnerability that arises when an attacker can manipulate XSLT transformations performed on the server.
XSLT is a language used to transform XML documents into other formats, such as HTML, and is commonly employed in web applications to generate content dynamically.

XSLT can be used to define a data format which is subsequently enriched with data from the XML document. XSLT data is structured similarly to XML. However, it contains XSL elements within nodes prefixed with the xsl-prefix. The following are some commonly used XSL elements:
- <xsl:template>: This element indicates an XSL template. It can contain a match attribute that contains a path in the XML document that the template applies to
- <xsl:value-of>: This element extracts the value of the XML node specified in the select attribute
- <xsl:for-each>: This element enables looping over all XML nodes specified in the select attribute
