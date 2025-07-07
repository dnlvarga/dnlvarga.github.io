---
layout: default
title: Linux PrivEsc
permalink: /linux_privesc/
---

# Enumeration Scripts

```
./linpeas.sh
```

# Kernel Exploits

e.g DirtyCow

# User Privileges

Another critical aspect to look for after gaining access to a server is the privileges available to the user we have access to. We can check what sudo privileges we have:
```
sudo -l
```

# Scheduled Tasks

- Add new scheduled tasks/cron jobs
- Trick them to execute a malicious software

# SSH Keys

If we have read access over the .ssh directory, we may read their private ssh keys found in /home/user/.ssh/id_rsa or /root/.ssh/id_rsa.
```
vim id_rsa
```
```
chmod 600 id_rsa
```
```
ssh root@10.10.10.10 -i id_rsa
```
The command 'chmod 600 id_rsa' on the key after we created it on our machine to change the file's permissions to be more restrictive. If ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.
