---
layout: default
title: XXE
permalink: /Web/xxe/
---

# XML External Entity (XXE) Injection
XXE Injection vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions.

## Local File Disclosure
When a web application trusts unfiltered XML data from user input, we may be able to reference an external XML DTD document and define new custom XML entities. Suppose we can define new entities and have them displayed on the web page. In that case, we should also be able to define external entities and make them reference a local file, which, when displayed, should show us the content of that file on the back-end server.

### Identifying
If we intercept an HTTP request and our data is send in an XML format to the web server, then it is a potential target. If the web application uses outdated XML libraries, and it does not apply any filters or sanitization on our XML input. In that case, we may be able to exploit this XML form to read local files. <br>
If we send a request and one element is displayed back to us, we can try to inject into that element. We can add e.g. the following lines after the first line the int XML input (the first line should look something like this: `<?xml version="1.0" encoding="UTF-8"?>`):
```
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
*Note: In this example, the XML input in the HTTP request had no DTD being declared within the XML data itself, or being referenced externally, so we added a new DTD before defining our entity. If the DOCTYPE was already declared in the XML request, we would just add the ENTITY element to it.*

Now, we should have a new XML entity called 'company', which we can reference with `&company;`. So, instead of using e.g. our email in the email element, we can try using `&company;`, and see whether it will be replaced with the value we defined ('Inlane Freight'):

*Note: Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm). If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.*

### Reading Files
To see if we can define external XML entities, we can add the SYSTEM keyword and define the external reference path after it:
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```
This enables us to read the content of sensitive files, like configuration files that may contain passwords or other sensitive files like an id_rsa SSH key of a specific user, which may grant us access to the back-end server.

*Note: In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.*
