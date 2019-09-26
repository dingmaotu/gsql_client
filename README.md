# gsql_client

## Introduction

If you are using TigerGraph, you probably know that there are only one way to remotely execute
 your GSQL scripts: gql_client.jar. This jar is an interactive console and you can not programmatically
 access GSQL server (until 2.4 TigerGraph introduces JDBC based access). But we love Python,
 right?

So here we are: a Python version of gsql_client, removing all interactive features. gsql_client.jar
actually uses http to interact with GSQL server. So can Python. TigerGraph already open sourced their
[client implementation](https://github.com/tigergraph/ecosys/tree/master/clients/com/tigergraph), but only
for versions later than 2.3.0. I originally wrote this for 2.2.3, so there are minor differences.
 
## Installation

Copy gsql_client folder to your project or install with pip:

```shell script
pip install gsql_client
```

This package has no external dependency and it is compatible with both Python 2 and 3.
 
> Note:
>
> if you submit large gsql files or long running commands, using remote client may receive
> IncompleteRead exception as TigerGraph nginx service does not properly configure the `proxy_read_timeout`
> for `/gsqlserver` path. So you may need to edit `{TIGERGRAPH_HOME}/tigergraph/config/nginx/nginx_1.conf`
> and add this option (like for `/admin/websocket` or `/websocket`).

## TODO

Maybe I could create a main function to launch an interactive shell (using stdlib cmd module), so that
we can use `python -m gsql_client` just as `java -jar gsql_client.jar`. It is best to keep them compatible
(for both command line options and behaviors).

## Usage

It contains mainly 2 classes: gsql_client.Client as a remote GSQL server client and
gsql_client.RESTPP for directly interact with RESTPP server.

```python
from gsql_client import Client, RESTPP

# default port 14240, you can use 10.0.0.1:29383 to specify another port
client = Client("10.0.0.1")
# for versions later than 2.4.0, it is mandatory to specify the version like this:
client = Client("10.0.0.1", version="v2_4_0")
# or the login would fail with incompatible server/client version
# you can directly specify the commit hash of the client (used for compatibility check) by:
client = Client("10.0.0.1", version="v2_6_0", commit="somehexhashstring")

client.login()  # returns True for success; exceptions and False for failure
res = client.command("ls")  # also returns the result as a list of lines
client.command("clear graph store", "y") # needs answer
client.run_file("yourfile.gsql")
client.version()
client.help()
client.quit()

restpp = RESTPP("10.0.0.1")  # default port 9000

# no need to login
# but you can use restpp.requesttoken(secret) to setup token based authentication:
secret = client.get_secret("my_graph", create_alias="my_graph_query_secret")

# use=True for directly using the requested token
token = restpp.request_token(secret, use=True)
# or with set_token
restpp.set_token(token)

# same as type `select * from MyVertex` in gsql shell
restpp.select_vertices("my_graph", "MyVertex")
restpp.query("my_graph", "my_query", param1 = 1)  # run your query
```