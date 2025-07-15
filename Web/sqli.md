---
layout: default
title: SQL Injection
permalink: /Web/sqli/
---

# SQL Injection

When user-supplied information is used to construct the query to the database, malicious users can trick the query into being used for something other than what the original programmer intended.
SQL injection refers to attacks against relational databases such as MySQL (whereas injections against non-relational databases, such as MongoDB, are NoSQL injection).

## MySQL
The `mysql` utility is used to authenticate to and interact with a MySQL/MariaDB database.
```
mysql -u root -h $host -P $port -p
```
*Note: The -p flag should be passed empty, so we are prompted to enter the password and do not pass it directly on the command line since it could be stored in cleartext in the bash_history file.
However, if you put the password in the command, there shouldn't be any spaces between '-p' and the password.*
*Note: The default MySQL/MariaDB port is 3306.*
### View Databases
```
SHOW DATABASES;
```
### Switch to Database
```
Use database_name;
```
### View Tables
```
SHOW TABLES;
```
### View Table Structure
```
DESCRIBE table_name;
```

