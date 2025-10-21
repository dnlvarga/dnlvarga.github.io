---
layout: default
title: Fuzzing
permalink: /Web/fuzzing/
---

# Tooling

## Installing Go, Python and PIPX
```sudo apt update```
```sudo apt install -y golang```
```sudo apt install -y python3 python3-pip```
```
sudo apt install pipx
pipx ensurepath
sudo pipx ensurepath --global
```
Checks:
```
go version
python3 --version
```

## Ffuf
```
go install github.com/ffuf/ffuf/v2@latest
```

## Gobuster
```
go install github.com/OJ/gobuster/v3@latest
```

## FeroxBuster
FeroxBuster is a recursive content discovery tool. It's more of a "forced browsing" tool than a fuzzer like ffuf.
```
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin
```

## wfuzz/wenum
You can replace wenum commands with wfuzz if necessary.
```
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

# Directory and File Fuzzing
 Hidden resources may contain sensitive information, backup files, configuration files, or even old, vulnerable application versions.
 Directory and file fuzzing involves systematically probing the web application with a list of potential directory and file names and analyzing the server's responses.

 ## Directory Fuzzing
 
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ
```

 ## File Fuzzing

 ```
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/<dir_name>/FUZZ.html -e .php,.html,.txt,.bak,.js -v
```

# Recursive Fuzzing
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion
```
The `-ic` option ignores commented lines in wordlists during fuzzing.
*Note: Excessive requests can overwhelm the target server.*
Other useful options:
- `-recursion-depth`: maximum depth for recursive exploration.
- `-rate`: the rate at which ffuf sends requests per second.
- `-timeout`: sets the timeout for individual requests, which prevents the fuzzer from hanging on unresponsive targets.
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
```

# Parameter and Value Fuzzing

## wenum
installation:
```
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```
Fuzz the "x" GET paramter's value:
```
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://IP:PORT/get.php?x=FUZZ"
```
- `--hc 404`: Hides responses with the 404 status code
Fuzz the "y" POST parameter's value and search for 200 OK status code:
```
ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```
After finding the value, we can validate with `curl`:
```
curl -d "y=<value>" http://IP:PORT/post.php
```

# Virtual Host and Subdomain Fuzzing
Virtual hosts are identified by the Host header in HTTP requests, while subdomains are	identified by DNS records, pointing to specific IP addresses.

## VHost Fuzzing
First add the specified vhost to our hosts file:
```
echo "IP example.com" | sudo tee -a /etc/hosts
```
Then:
```
gobuster vhost -u http://example.com:$port -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```
- `--append-domain`: append the base domain to each word in the wordlist.

## Subdomain Fuzzing
```
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
 If a subdomain resolves to an IP address, it is considered valid and included in the output.

# Filtering

## Gobuster
- `-s`: Includes only responses with the specified status codes (comma-separated).
- `-b`: Excludes responses with specified status codes (comma-separated).
- `--exclude-length`: Excludes responses with specified content lengths (comma-separated, support ranges).
```
gobuster dir -u http://example.com/ -w wordlist.txt -s 200,301 --exclude-length 0
```

## Ffuf
*Note: By default, ffuf matches only specific status codes to minimize noise from 404 NOT FOUND.*
- `-mc`: Match code. (Include only responses that match the specified status codes. We can give a list or specify ranges.)
  *Note: We can use `-mc all` too.*
- `-fc`: Filter code.
- `-fs`: Filter size.
- `-ms`: Match size.
- `-fw`: Filter number of words.
- `-mw`: Match word count.
- `-fl`: Filter line number.
- `-ml`: Match line count.
- `-mt`: Match time. E.g. `-mt >500`.

```
ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200 -fw 427 -ms >500
```

## Wenum
- `--hc`: Hide code.
- `--sc`: Show code.
- `--hl`: Hide length.
- `--sl`: Show length.
- `--hw`: Hide word.
- `--sw`: Show word.
- `--hs`: Hide size.
- `--ss`: Show size.
- `--hr`: Hide regex. E.g.: `-hr "Internal Server Error".`
- `--sr`: Show regex. E.g.: `-sr "admin"`
- `--filter` or `--hard-filter`: General-purpose filter to show/hide responses or prevent their post-processing using a regular expression. `--filter "Login"` will show only responses containing "Login", while `--hard-filter "Login"` will hide them and prevent any plugins from processing them.

```
wenum -w wordlist.txt --sc 200,301,302 -u https://example.com/FUZZ
```

## Feroxbuster
- `--dont-scan`: Exclude specific URLs or patterns from being scanned. E.g. `--dont-scan /uploads`
- `-S`, `--filter-size`: Exclude responses based on their size.
- ...

```
feroxbuster --url http://example.com -w wordlist.txt -s 200 -S 10240 -X "error" 
```

## Validating
```
curl -I http://IP:PORT/backup/password.txt
```
And check the file size in the `Content-Length` value.
By focusing on headers, we can gather valuable information without directly accessing the file's contents (responsible disclosure practices).

# Identifying endpoints
## REST API
Endpoints in REST APIs are structured as URLs representing the resources.
Examples:
- /users
- /users/123
- /products

Parameters:
- Query paremters: `/users?limit=10&sort=name`
- Path parameters: `/products/{id}pen_spark`
- Request Body Parameters: `{ "name": "New Product", "price": 99.99 }`

Discovering enpoints and paramters:
- API Documentation. Look for specifications like Swagger (OpenAPI) or RAML.
  *Note: There could be hidden endpoints missing from the documentation.*
- Network Traffic Analysis. Tools like Burp Suite or your browser's developer tools allow us to intercept and inspect API requests and responses, revealing endpoints, parameters, and data formats.
- Parameter Name Fuzzing.

## SOAP API
Unlike REST APIs, which use distinct URLs for each resource, SOAP APIs typically expose a single endpoint. This endpoint is a URL where the SOAP server listens for incoming requests. SOAP parameters are defined within the body of the SOAP message, an XML document.

Discovering SOAP endpoints and parameters:
- WSDL Analysis. We can also use tools designed to parse and visualize WSDL structures.
- Network Traffic Analysis. We can intercept and analyze traffic as with REST APIs. We can also use Wireshark or tcpdump.
- Fuzzing. We can try to send malformed or unexpected values within SOAP requests and see how the server responds.

## GraphQL API
Example:
```
query {
  user(id: 123) {
    name
    email
    posts(limit: 5) {
      title
      body
    }
  }
}
```
GraphQL Mutations: Mutations are the counterparts to queries designed to modify data on the server. They encompass operations to create, update, or delete data.
Example:
```
mutation {
  createPost(title: "New Post", body: "This is the content of the new post") {
    id
    title
  }
}
```

Discovering Queries and Mutations:
- GraphQL's introspection system. By sending an introspection query to the GraphQL endpoint, you can retrieve a complete schema describing the API's capabilities.
- API Documentation.
- Network Traffic Analysis.

# API fuzzing
The goal is to trigger API errors, crashes, or unexpected behavior, revealing potential vulnerabilities like input validation flaws, injection attacks, or authentication issues.

Types of API Fuzzing:
- Parameter Fuzzing
- Data Format Fuzzing
- Sequence Fuzzing (By manipulating the order, timing, or parameters of API calls, fuzzers can expose weaknesses in the API's logic and state management.)

# Fuzzing API
```
git clone https://github.com/PandaSt0rm/webfuzz_api.git
cd webfuzz_api
pip3 install -r requirements.txt
```
Then:
```
python3 api_fuzzer.py http://IP:PORT
```
Then you can use `curl` to make API call.

Some scenario:
- Broken Object-Level Authorization: Fuzzing could reveal instances where manipulating parameter values can allow unauthorized access to specific objects or resources.
- Broken Function Level Authorization: Fuzzing might uncover cases where unauthorized function calls can be made.
- Server-Side Request Forgery (SSRF): Injections of malicious values into parameters could trick the server into making unintended requests to internal or external resources.






