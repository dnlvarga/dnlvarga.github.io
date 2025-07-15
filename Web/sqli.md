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
## Few SQL Statements
### INSERT
Add new records to a given table.
```
INSERT INTO logins VALUES(1, 'admin', 'password', '2025-07-15');
```
```
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
```
### SELECT
Retrieve data.
```
SELECT * FROM table_name;
```
### UPDATE
update specific records.
```
UPDATE logins SET password = 'change_password' WHERE id > 1;
```
### LIMIT
In case our query returns a large number of records, we can limit the results.
```
SELECT * FROM logins LIMIT 2;
```
### WHERE
To filter or search.
```
SELECT * FROM logins WHERE id > 1;
```
### LIKE
Enables selecting records by matching a certain pattern.
Records  with usernames starting with admin:
```
SELECT * FROM logins WHERE username LIKE 'admin%';
```
### SQL Operators
```
SELECT 1 = 1 AND 'test' = 'test';
```
```
SELECT 1 = 1 OR 'test' = 'abc';
```
```
SELECT NOT 1 = 1;
```
The AND, OR and NOT operators can also be represented as &&, || and !, respectively.
```
SELECT * FROM logins WHERE username != 'john' AND id > 1;
```
## Database Enumeration

