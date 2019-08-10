# gsql_client

## Introduction

If you are using TigerGraph, you probably know that there are only one way to remotely execute
 your GSQL scripts: gql_client.jar. This jar is an interactive console and you can not programmatically
 access GSQL server (until 2.4 TigerGraph introduces JDBC based access). But we love Python,
 right?

So here we are: a Python version of gsql_client, removing all interactive features. gsql_client.jar
actually uses http to interact with GSQL server. So can Python. I already made the suggestion to
 TigerGraph that they should open up the protocol between GSQL server and gsql_client.jar, so that
 others can create clients in whatever language they like. This will foster a much better
 developer community.
 
## Installation

Copy gsql_client folder to your project. I have not write setup.py scripts and put this on PyPI,
 but I am going to.

## Usage

```python
from gsql_client import Client

client = Client("10.0.0.1")

client.login()  # returns True for success; exceptions and False for failure

res = client.command("ls")  # also returns the result

client.command("clear graph store", "y") # needs answer

client.run_file("yourfile.gsql")

client.version()

client.help()

client.quit()
```