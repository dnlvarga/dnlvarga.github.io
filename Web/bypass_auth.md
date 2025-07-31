---
layout: default
title: Bypassing Authentication
permalink: /Web/bypass_auth/
---

We will mainly focus on knowledge-based authentication.

# User Enumeration
- Web applications could reveal whether a username exists or not by showing different error messages for the two cases or a chat application might show other users by username to chat with.
- A good starting point is the wordlist collection [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames).
```
ffuf -w /path/to/xato-net-10-million-usernames.txt -u http://$ip/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"
```
- Side-channel attacks do not directly target the web application's response but rather extra information that can be obtained or inferred from the response, e.g. the time it takes for the web application's response to reach us.

# Brute-Forcing Passwords
Ensuring that a good wordlist is used for the attack is crucial.
If a web application enforces a password policy, we should ensure that our wordlist only contains passwords that match the implemented password policy.
```
grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```
```
wc -l custom_wordlist.txt
```
```
ffuf -w ./custom_wordlist.txt -u http://$ip/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"
```
# Brute-Forcing Password Reset Tokens
Many web applications implement a password-recovery functionality if a user forgets their password. This password-recovery functionality typically relies on a one-time reset token, which is transmitted to the user, for instance, via SMS or E-Mail. The user can then authenticate using this token, enabling them to reset their password and access their account.
As such, a weak password-reset token may be brute-forced or predicted by an attacker to take over a victim's account. <br>
To identify weak reset tokens, we typically need to create an account on the target web application, request a password reset token, and then analyze it. <br>
In case of 4 digit reset token:
```
seq -w 0 9999 > tokens.txt
```
The -w flag pads all numbers to the same length by prepending zeroes.
Verify with `head token.txt`.
```
ffuf -w ./tokens.txt -u http://$domain/reset_password.php?token=FUZZ -fr "The provided token is invalid"
```
# Brute-Forcing 2FA Codes

One of the most common 2FA implementations relies on the user's password and a time-based one-time password (TOTP) provided to the user's smartphone by an authenticator app or via SMS. These TOTPs typically consist only of digits.

```
seq -w 0 9999 > tokens.txt
```
```
ffuf -w ./tokens.txt -u http://$domain/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=mrjm73bh8e53qcej2744h7k44p" -d "otp=FUZZ" -fr "Invalid 2FA Code"
```
With that we will get hits after the session successfully passed the 2FA check because we had supplied the correct TOTP. The first hit was the correct TOTP. Afterward, our session is marked as fully authenticated, so all requests using our session cookie are redirected to the logged in page.
## Rate Limits
A rate limit should only be enforced on an attacker, not regular users, to prevent DoS scenarios. Many rate limit implementation rely on the IP address to identify the attacker. However, there are middleboxes such as reverse proxies, load balancers, or web caches, a request's source IP address will belong to the middlebox, not the attacker. Thus, some rate limits rely on HTTP headers such as X-Forwarded-For to obtain the actual source IP address. This causes an issue as an attacker can set arbitrary HTTP headers in request, bypassing the rate limit entirely.
## CAPTCHAs
The abbreviation stands for: Completely Automated Public Turing test to tell Computers and Humans Apart, although these test could be solved with AI nowadays (see this [link](https://arstechnica.com/information-technology/2025/07/openais-chatgpt-agent-casually-clicks-through-i-am-not-a-robot-verification-test/)). There are many open-source CAPTCHA solvers too.

# Testing Default Credentials
[CIRT.net](https://www.cirt.net/passwords) is a database for default credentials. Further resources include [SecLists Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials) as well as the [SCADA](https://github.com/scadastrangelove/SCADAPASS/tree/master) GitHub repository which contains a list of default passwords for a variety of different vendors.
You should always search for default credentials in case you find the used technology/device.

# Vulnerable Password Reset
## Guessable Password Reset Questions
These questions can often be obtained through OSINT or guessed, given a sufficient number of attempts, i.e., a lack of brute-force protection. <br>
For instance, [this](https://github.com/datasets/world-cities/blob/main/data/world-cities.csv) CSV file contains a list of more than 25,000 cities with more than 15,000 inhabitants from all over the world.
```
cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt
```
We could narrow down the cities if we had additional information:
```
cat world-cities.csv | grep Germany | cut -d ',' -f1 > german_cities.txt
```
Check:
```
wc -l german_cities.txt
```
Brute-force the answer:
```
ffuf -w ./german_cities.txt -u http://$ip:$port/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" -d "security_response=FUZZ" -fr "<incorrect_response>"
```
## Manipulating the Reset Request
Another instance of a flawed password reset logic occurs when a user can manipulate a potentially hidden parameter to reset the password of a different account.
Suppose supplying the security response London results in the following request:
```
POST /security_question.php HTTP/1.1
Host: pwreset.htb
Content-Length: 43
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

security_response=London&username=htb-stdnt
```
So the username is contained in the form as a hidden parameter and sent along with the security response. Then we can reset the user's password and the final request looks like this:
```
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Length: 36
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

password=P@$$w0rd&username=htb-stdnt
```
Like the previous request, the request contains the username in a separate POST parameter. Suppose the web application does properly verify that the usernames in both requests match. In that case, we can skip the security question or supply the answer to our security question and then set the password of an entirely different account.

# Direct Access
The most straightforward way of bypassing authentication checks is to request the protected resource directly from an unauthenticated context. It might work if the web application does not properly verify that the request is authenticated. <br>
To illustrate the vulnerability, let us assume the web application redirects the user to /index.php if the session is not active, i.e., if the user is not authenticated. However, the PHP script does not stop execution, resulting in protected information within the page being sent in the response body, so the entire admin page is contained in the response body. If we attempt to access the page in our web browser, the browser follows the redirect and displays the login prompt instead of the protected admin page. We can easily trick the browser into displaying the admin page by intercepting the response and changing the status code from 302 to 200. <br>
To do this, enable Intercept in Burp. Afterward, browse to the /admin.php endpoint in the web browser. Next, right-click on the request and select Do intercept > Response to this request to intercept the response. Afterward, forward the request by clicking on Forward. Since we intercepted the response, we can now edit it. To force the browser to display the content, we need to change the status code from 302 Found to 200 OK.

# Parameter Modification

Let's say after logging in as a user, we are redirected to `/admin.php?user_id=183`. To investigate the purpose of the user_id parameter, let us remove it from our request to /admin.php. When doing so, we are redirected back to the login screen at /index.php, even though our session provided in the PHPSESSID cookie is still valid.<br>
Based on the parameter name user_id, we can infer that the parameter specifies the ID of the user accessing the page. If we can guess or brute-force the user ID of an administrator, we might be able to access the page with administrative privileges.


