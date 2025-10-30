---
layout: default
title: API attacks
permalink: /Web/API/
---

# OWASP API Top 10 Security Risks using a RESTful web API

## Broken Object Level Authorization (BOLA)
Web APIs allow users to request data or records by sending various parameters, including unique identifiers such as Universally Unique Identifiers (UUIDs), also known as Globally Unique Identifiers (GUIDs), and integer IDs. Failing to properly verify that a user has permission to view a specific resource through object-level authorization mechanisms can lead to security vulnerabilities.
BOLA also known as an Insecure Direct Object Reference (IDOR) vulnerability.

Mass abuse BOLA from terminal:
```
for ((i=1; i<=20; i++));
do curl -s -w "\n" -X 'GET' \
'http://$ip:$port/endpoint/'$i'' \
-H 'accept: application/json' \
-H 'Authorization: Bearer eyJhbG<SNIP>' | jq;
done
```

## Broken Authentication
No rate-limiting on the endpoint, so brute-forcing is possible.
```
ffuf -w /opt/useful/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASS -w customerEmails.txt:EMAIL -u http://$ip:$port/api/v1/authentication/customers/sign-in -X POST -H "Content-Type: application/json" -d '{"Email": "EMAIL", "Password": "PASS"}' -fr "Invalid Credentials" -t 100
```
### Brute-forcing OTPs and Answers of Security Questions
If brute-forcing passwords is infeasible due to strong password policies, we can attempt to brute-force OTPs or answers to security questions to reset passwords.
Send a password reset and then fuzz the OTP:
```
ffuf -u http://$ip:$port/api/v1/authentication/customers/passwords/resets \
-X POST \
-H "accept: application/json" \
-H "Content-Type: application/json" \
-d '{"Email":"$email","OTP":"FUZZ","NewPassword":"123456"}' \
-w /opt/useful/seclists/Fuzzing/4-digits-0000-9999.txt
```
## Broken Object Property Level Authorization
### Excessive Data Exposure
Example: Exposure of Sensitive Information Due to Incompatible Policies. <br>
It is typical for e-commerce marketplaces to allow customers to view supplier details. However, if the response after invoking the `/api/v1/suppliers GET` endpoint includes also the email and phoneNumber fields of the suppliers, then costumers can circumvent the marketplace entirely and contact suppliers directly to purchase goods (at a discounted price).

### Mass Assignment
Example: Improperly Controlled Modification of Dynamically-Determined Object Attributes. <br>
Maybe the `/api/v1/supplier-companies PATCH` endpoint allows sending a value for the isExemptedFromMarketplaceFee field, making the a company not get included in the companies required to pay the marketplace fee.

## Unrestricted Resource Consumption
A web API is vulnerable to Unrestricted Resource Consumption if it fails to limit user-initiated requests that consume resources such as network bandwidth, CPU, memory, and storage. 
We might be able to upload files without proper limitations or spamming an endpoint uncontrollably.

## Broken Function Level Authorization (BFLA)
A web API is vulnerable to BFLA if it allows unauthorized or unprivileged users to interact with and invoke privileged endpoints, granting access to sensitive operations or confidential information.

## Unrestricted Access to Sensitive Business Flows
Example: Access to product discount data which leads to Unrestricted Access to Sensitive Business Flows because it allows us to know the dates when supplier companies will discount their products and the corresponding discount rates. Combined with an Unrestricted Resource Consumption vulnerability, we can purchase all available stock on the day the discount starts and resell the products later.

## Server-Side Request Forgery (SSRF)
A web API is vulnerable to Server-Side Request Forgery (SSRF) (also known as Cross-Site Port Attack (XPSA)) if it uses user-controlled input to fetch remote or local resources without validation.
This vulnerability can be present, if one endpoint let's us modify fields such as File URIs. We can make this value to point to local data, e.g `/etc/passwd`. After setting this value, maybe we can find another endpoint to fetch this data.

