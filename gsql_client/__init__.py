# -*- coding: utf-8 -*-

# for python 2 and 3 compatibility, we import these anyway
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

import re
import io
import base64
import json
import logging
import codecs
from os import getenv
from os.path import expanduser, isfile

# import http client
try:
    # noinspection PyCompatibility
    from urllib.parse import quote_plus, urlencode
    # noinspection PyCompatibility
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from urllib import quote_plus, urlencode
    # noinspection PyCompatibility
    from httplib import HTTPConnection, HTTPSConnection

# import ssl
# notice that Python might not be compiled with ssl support
try:
    # noinspection PyUnresolvedReferences
    import ssl

    HAS_SSL = True
except ImportError:
    HAS_SSL = False


class AuthenticationFailedException(Exception):
    """
    Exception thrown when RESTPP or GSQL client authentication failed
    """
    pass


class RecursiveIncludeException(Exception):
    """
    Exception thrown when recursively include an already included source during GSQL import (@file)
    """
    pass


class ReturnCodeException(Exception):
    """
    Exception thrown when executing a GSQL file or multiple commands

    Usually, when submitting a file to GSQL Server, if any command is preventing the whole file from executing,
    an internal code is returned. But if failed commands are not fatal, then it will be fine and no exception is raised.
    """
    pass


# these are interal special codes for interactive use
# we include them anyway though these are not currently used.
# we will need them later if an interactive shell is added to this library
PREFIX_CURSOR_UP = "__GSQL__MOVE__CURSOR___UP__"
PREFIX_CLEAN_LINE = "__GSQL__CLEAN__LINE__"
PREFIX_INTERACT = "__GSQL__INTERACT__"
PREFIX_RET = "__GSQL__RETURN__CODE__"
PREFIX_COOKIE = "__GSQL__COOKIES__"

# these regex are for matching GSQL Server interactive output
FILE_PATTERN = re.compile("@[^@]*[^;,]")
PROGRESS_PATTERN = re.compile("\\[=*\\s*\\]\\s[0-9]+%.*")
COMPLETE_PATTERN = re.compile("\\[=*\\s*\\]\\s100%[^l]*")

# the following are for parsing `ls` output
NULL_MODE = 0
VERTEX_MODE = 1
EDGE_MODE = 2
GRAPH_MODE = 3
JOB_MODE = 4
QUERY_MODE = 5
TUPLE_MODE = 6

CATALOG_MODES = {
    "Vertex Types": VERTEX_MODE,
    "Edge Types": EDGE_MODE,
    "Graphs": GRAPH_MODE,
    "Jobs": JOB_MODE,
    "Queries": QUERY_MODE,
    "User defined tuples": TUPLE_MODE
}


def _is_mode_line(line):
    """
    `ls` output starts a category with a separate line like `Vertex Types:`, we need to recognize this line
    to know what follows it.
    """
    return line.endswith(":")


def _get_current_mode(line):
    """
    We match the mode string with formal constants. This might change. I hope RESTPP or some formal api spec
    can be used to get catalog programmatically.
    """
    return CATALOG_MODES.get(line[:-1], NULL_MODE)


def _parse_catalog(lines):
    """
    parse output of `ls`
    return a dict of:
        vertices: ["VertexType1", ...]
        edges: ["EdgeType1", ...]
        graphs: ["Graph1", ...]
        jobs: ["Job1", ...]
        queries: ["Query1", ...]
    No detail is returned. Use this function to get an overview of what is available or if something exists.
    """
    vertices = []
    edges = []
    graphs = []
    jobs = []
    queries = []
    tuples = []

    current_mode = NULL_MODE

    for line in lines:
        line = line.strip()
        if _is_mode_line(line):
            current_mode = _get_current_mode(line)
            continue

        if line.startswith("- "):
            line = line[2:]
            if current_mode == VERTEX_MODE:
                e = line.find("(")
                vertices.append(line[7:e])
            elif current_mode == EDGE_MODE:
                s = line.find("EDGE ") + 5
                e = line.find("(")
                edges.append(line[s:e])
            elif current_mode == GRAPH_MODE:
                s = line.find("Graph ") + 6
                e = line.find("(")
                graphs.append(line[s:e])
            elif current_mode == JOB_MODE:
                s = line.find("JOB ") + 4
                e = line.find(" FOR GRAPH")
                jobs.append(line[s:e])
            elif current_mode == QUERY_MODE:
                e = line.find("(")
                queries.append(line[:e])
            elif current_mode == TUPLE_MODE:
                e = line.find("(")
                tuples.append(line[:e].strip())
    return {
        "vertices": vertices,
        "edges": edges,
        "graphs": graphs,
        "jobs": jobs,
        "queries": queries,
        "tuples": tuples
    }


def get_option(option, default=""):
    """
    This function mimics the Java version: read config from a local configuration file
    """
    cfg_path = expanduser("~/.gsql/gsql.cfg")
    with open(cfg_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith(option):
                values = line.split()
                if len(values) >= 2:
                    return values[1]
    return default


# since 2.4.0, TigerGraph Client uses a commitClient cookie parameter for login to verify compatibility
# we track https://github.com/tigergraph/ecosys/clients/com/tigergraph/ to update this mapping
VERSION_COMMIT = {
    "v2_4_0": "f6b4892ad3be8e805d49ffd05ee2bc7e7be10dff",
    "v2_4_1": "47229e675f792374d4525afe6ea10898decc2e44",
    "v2_5_0": "bc49e20553e9e68212652f6c565cb96c068fab9e"
}


class Client(object):
    """
    Main class of the GSQL client
    """

    def __init__(self, server_ip="127.0.0.1", username="tigergraph", password="tigergraph", cacert="",
                 version="", commit=""):
        """
        Create a client from remote server ip, username, and password
        `cacert` is a path to certificates. See Python ssl module documentation for reference.
        """
        self._logger = logging.getLogger("gsql_client.Client")
        self._server_ip = server_ip
        self._username = username
        self._password = password

        if commit:
            self._client_commit = commit
        elif version in VERSION_COMMIT:
            self._client_commit = VERSION_COMMIT[version]
        else:
            self._client_commit = ""

        self._version = version

        if self._version and self._version >= "v2_3_0":
            self._abort_name = "abortclientsession"
        else:
            self._abort_name = "abortloadingprogress"

        if cacert and HAS_SSL:
            self._context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_REQUIRED
            self._context.load_verify_locations(cacert)
            self._protocol = "https"
        else:
            self._context = None
            self._protocol = "http"

        # we encode the credential for Basic HTTP authentication
        self.base64_credential = base64.b64encode(
            "{0}:{1}".format(self._username, self._password).encode("utf-8")).decode("utf-8")

        # if server is local or remote; GSQL Server is exposed under different paths for different situations
        self.is_local = server_ip.startswith("127.0.0.1") or server_ip.startswith("localhost")

        if self.is_local:
            self._base_url = "/gsql/"  # local base url
            if ":" not in server_ip:
                port = get_option("gsql.server.private_port", "8123")
                self._server_ip = "{0}:{1}".format(server_ip, port)
        else:
            self._base_url = "/gsqlserver/gsql/"  # remote base url; actually an nginx proxy to the local one
            if ":" not in server_ip:
                self._server_ip = "{0}:{1}".format(server_ip, "14240")

        # create various command urls
        self._initialize_url()

        # cookies (session properties)
        self.graph = ""
        self.session = ""
        self.properties = ""

        self.authorization = 'Basic {0}'.format(self.base64_credential)

    def _initialize_url(self):
        self.command_url = self._base_url + "command"
        self.version_url = self._base_url + "version"
        self.help_url = self._base_url + "help"
        self.login_url = self._base_url + "login"
        self.reset_url = self._base_url + "reset"
        self.file_url = self._base_url + "file"
        self.dialog_url = self._base_url + "dialog"

        self.info_url = self._base_url + "getinfo"
        self.abort_url = self._base_url + self._abort_name

    def _get_cookie(self):
        """
        GSQL Client interaction with the server needs proper cookies
        We especially need TERMINAL_WIDTH for the request to work, though this library is not interactive (for now)
        """
        cookie = {}
        if self.is_local:
            cookie["CLIENT_PATH"] = expanduser("~")

        cookie["GSHELL_TEST"] = getenv("GSHELL_TEST")
        cookie["COMPILE_THREADS"] = getenv("GSQL_COMPILE_THREADS")
        cookie["TERMINAL_WIDTH"] = 80

        if self.graph:
            cookie["graph"] = self.graph

        if self.session:
            cookie["session"] = self.session

        if self.properties:
            cookie["properties"] = self.properties

        if self._client_commit:
            cookie["commitClient"] = self._client_commit

        return json.dumps(cookie, ensure_ascii=True)

    def _set_cookie(self, cookie_str):
        """
        update session properties
        """
        cookie = json.loads(cookie_str)
        self.session = cookie.get("session", "")
        self.graph = cookie.get("graph", "")
        self.properties = cookie.get("properties", "")

    def _setup_connection(self, url, content, cookie=None, auth=True):
        """
        We use HTTPConnection directly instead of urlib or urllib2. It is much cleaner and has all low level options.

        urllib has some limitations. For example, you can not specify HTTP request method.
        If you use Ruquest object and set Request.method = lambda x: "POST", then PySpark will have problem serialize
        the method. Since this library are used with PySpark (for parallel actions for each partition), urllib is really
        not acceptable.

        We also don't want to introduce third party dependencies. So requests and urllib3 are not used.

        :param url: url of the request
        :param content: for POST content, a string, and it will be formatted as utf-8 url encoded
        :param cookie: dict of cookie values, will be merged with the default one
        :param auth: authorization token; you can override the default Basic authentication
        :return: a HTTP(S)Connection object
        """
        if self._protocol == "https":
            conn = HTTPSConnection(self._server_ip, context=self._context)
        else:
            conn = HTTPConnection(self._server_ip)
        encoded = quote_plus(content.encode("utf-8"))
        headers = {
            "Content-Language": "en-US",
            "Content-Length": str(len(encoded)),
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Java/1.8.0",
            "Cookie": self._get_cookie() if cookie is None else cookie
        }
        if auth:
            headers["Authorization"] = self.authorization
        conn.request("POST", url, encoded, headers)
        return conn

    def _request(self, url, content, handler=None, cookie=None, auth=True):
        """
        This is the method used for all requests to the GSQL Server.

        It actually does 3 things:
            1. call _setup_connection
            2. check authentication failure
            3. convert the result to text stream for handler or directly return the response as text

        :param url: see `_setup_connection` parameter `url`
        :param content: see `_setup_connection` parameter `content`
        :param handler: a function that handle the response as text stream; if not specified,
                        the whole content will be utf-8 decoded and returned
        :param cookie: see `_setup_connection` parameter `cookie`
        :param auth: see `_setup_connection` parameter `auth`
        :return: handler result if specified or response as utf-8 decoded text
        """
        response = None
        try:
            r = self._setup_connection(url, content, cookie, auth)
            response = r.getresponse()
            ret_code = response.status
            if ret_code == 401:
                raise AuthenticationFailedException("Invalid Username/Password!")
            if handler:
                reader = codecs.getreader("utf-8")(response)
                return handler(reader)
            else:
                return response.read().decode("utf-8")
        finally:
            if response:
                response.close()

    def _dialog(self, response):
        """
        Call dialog url.
        This is used for interactive command that needs user input (thus need a second request to complete).
        The input is send to the dialog url to complete the command.

        :param response the use response as text
        :return dialog response as text
        """
        self._request(self.dialog_url, response)

    def _command_interactive(self, url, content, ans="", out=True):
        """
        process response with special return codes. This is main workhorse for various one line commands.
        """

        def __handle__interactive(reader):
            """
            This function handles special interacive features. It mimics the Java version.
            """
            res = []
            for line in reader:
                line = line.strip()
                if line.startswith(PREFIX_RET):
                    _, ret = line.split(",", 1)
                    ret = int(ret)
                    if ret != 0:
                        raise ReturnCodeException(ret)
                elif line.startswith(PREFIX_INTERACT):
                    _, it, ik = line.split(",", 2)
                    if it in {"DecryptQb", "AlterPasswordQb", "CreateUserQb", "CreateTokenQb", "ClearStoreQb"} \
                            and ans:
                        self._dialog("{0},{1}".format(ik, ans))
                elif line.startswith(PREFIX_COOKIE):
                    _, cookie_s = line.split(",", 1)
                    self._set_cookie(cookie_s)
                elif line.startswith(PREFIX_CURSOR_UP):
                    values = line.split(",")
                    print("\033[" + values[1] + "A")
                elif line.startswith(PREFIX_CLEAN_LINE):
                    print("\033[2K")
                elif PROGRESS_PATTERN.match(line):
                    if COMPLETE_PATTERN.match(line):
                        line += "\n"
                    print("\r" + line)
                else:
                    if out:
                        print(line)
                    res.append(line)
            return res

        return self._request(url, content, __handle__interactive)

    def login(self):
        """
        Login to the GSQL Server. You can a unique session number for each login.

        The login method put the authentication string in the post content instead of request header, so it needs its
        own logic instead of reusing self._request
        """
        response = None
        try:
            r = self._setup_connection(self.login_url, self.base64_credential, auth=False)
            response = r.getresponse()
            ret_code = response.status
            if ret_code == 200:
                content = response.read()
                res = json.loads(content.decode("utf-8"))

                if "License expired" in res.get("message", ""):
                    raise Exception("TigerGraph Server License is expired! Please update your license!")

                compatible = res.get("isClientCompatible", True)
                if not compatible:
                    raise Exception("This client is not compatible with target TigerGraph Server!"
                                    " Please specify a correct version when creating this client!")

                if res.get("error", False):
                    if "Wrong password!" in res.get("message", ""):
                        raise AuthenticationFailedException("Invalid Username/Password!")
                    else:
                        raise Exception("Login failed!")
                else:
                    self.session = response.getheader("Set-Cookie")
                    return True
        finally:
            if response:
                response.close()

    def get_auto_keys(self):
        """
        This method is called right after login in the interactive shell scenario for auto completing.
        Not used here (for now).
        """
        keys = self._request(self.info_url, "autokeys", cookie=self.session)
        return keys.split(",")

    def quit(self):
        """
        quit current session
        """
        self._request(self.abort_url, self._abort_name)

    def command(self, content, ans=""):
        """
        send a single command to GSQL Server. If the command need furthur user input, you can specify directly in `ans`
        parameter and it will can self.dialog for you
        """
        return self._command_interactive(self.command_url, content, ans)

    def use(self, graph):
        """
        change current graph; self.graph session property will be changed if successful.
        """
        return self._command_interactive(self.command_url, "use graph {0}".format(graph))

    def catalog(self):
        """
        show and parse the output of `ls` command
        """
        lines = self._command_interactive(self.command_url, "ls", out=False)
        return _parse_catalog(lines)

    def _load_file_recursively(self, file_path):
        """
        load a GSQL file recursively (handle @file import)
        """
        return self._read_file(file_path, set())

    def _read_file(self, file_path, loaded):
        """
        read a GSQL file. `loaded` is the already loaded (included) files.
        """
        if not file_path or not isfile(file_path):
            self._logger.warn("File \"" + file_path + "\" does not exist!")
            return ""

        if file_path in loaded:
            self._logger.error("There is an endless loop by using @" + file_path + " cmd recursively.")
            raise RecursiveIncludeException(file_path)
        else:
            loaded.add(file_path)

        res = ""
        with io.open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if FILE_PATTERN.match(line):
                    res += self._read_file(line[1:], loaded) + "\n"
                    continue
                res += line + "\n"
        return res

    def run_file(self, path):
        """
        load the file at `path`, and submit the content to file_url
        """
        content = self._load_file_recursively(path)
        return self._command_interactive(self.file_url, content)

    def run_multiple(self, lines):
        """
        directly submit multiple commands to file_url (just like running a file)
        """
        return self._command_interactive(self.file_url, "\n".join(lines))

    def version(self):
        """
        show version string; can be used for debugging
        """
        return self._command_interactive(self.version_url, "version")

    def help(self):
        """
        show help string; can be used for debugging.

        this help is actually for Java version of gsql client. So it is basically no use here.
        """
        return self._command_interactive(self.help_url, "help")


class RESTPPError(Exception):
    """
    RESTPP server specific error.

    All other errors (including http connection errors) are raised directly. User need to handle them if they wanted.
    """
    pass


class RESTPP(object):
    """
    RESTPP is the TigerGraph RESTful API server. It is well documented and the following code are based on
    the official documentation.
    """

    def __init__(self, server_ip):
        """
        Initialize the client. Mainly record the IP (and port) of the server
        :param server_ip: can be 127.0.0.1 or 127.0.0.1:8983 for another port
        """
        self._token = ""
        if ":" in server_ip:
            self._server_ip = server_ip
        else:
            self._server_ip = server_ip + ":9000"

        self._logger = logging.getLogger("gsql_client.RESTPP")

    def _setup_connection(self, method, endpoint, parameters, content):
        """
        RESTPP follow RESTful API general guidelines.
        :param method: method can be "GET"/"POST"/"DELETE" based on specific endpoint requirements
        :param endpoint: the url of the request
        :param parameters: dict of parameters appending to the url
        :param content: POST contents (usually json string)
        :return: HTTPConnection object
        """
        url = endpoint
        if parameters:
            url += "?" + urlencode(parameters)

        headers = {
            "Content-Language": "en-US",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/json"
        }

        if content:
            encoded = content.encode("utf-8")
            headers["Content-Length"] = str(len(encoded))
        else:
            encoded = None

        if self._token:
            headers["Authorization"] = "Bearer: {0}".format(self._token)

        conn = HTTPConnection(self._server_ip)
        conn.request(method, url, encoded, headers)
        return conn

    def _request(self, method, endpoint, parameters=None, content=None):
        """
        This is the method used for all endpoint specific methods. It mainly does the following:
          1. check authentication failure
          2. convert the result to json
          3. check the json result for error code and message
        """
        response = None
        try:
            r = self._setup_connection(method, endpoint, parameters, content)
            response = r.getresponse()
            ret_code = response.status
            if ret_code == 401:
                raise AuthenticationFailedException("Invalid token!")
            response_text = response.read().decode("utf-8")
            self._logger.debug(response_text)
            # non strict mode to allow control characters in string
            res = json.loads(response_text, strict=False)

            # notice that result is not consistent, we need to handle them differently
            if "error" not in res:
                return res
            elif res["error"] and res["error"] != "false":  # workaround for GET /version result
                self._logger.error("API error: " + res["message"])
                raise RESTPPError(res.get("message", ""))
            elif "results" not in res:
                return res["message"]
            else:
                return res["results"]
        finally:
            if response:
                response.close()

    def _get(self, endpoint, parameters=None):
        return self._request("GET", endpoint, parameters, None)

    def _post(self, endpoint, parameters=None, content=None):
        return self._request("POST", endpoint, parameters, content)

    def _delete(self, endpoint, parameters=None):
        return self._request("DELETE", endpoint, parameters, None)

    def request_token(self, secret, lifetime=None):
        """
        Get an OAuth2 like token for later use.
        :param secret: generated by GSQL client
        :param lifetime: life time of the token in seconds
        :return: True if successfully updated internal token and otherwise False
        """
        parameters = {
            "secret": secret
        }
        if lifetime:
            parameters["lifetime"] = lifetime

        res = self._get("/requesttoken", parameters)
        if res:
            self._token = res
            return True
        else:
            return False

    def echo(self):
        """
        echo hello from TigerGraph RESTPP server; for debugging
        """
        return self._get("/echo")

    def version(self):
        """
        show versions of various components of the TigerGraph system
        """
        return self._get("/version")

    def endpoints(self):
        """
        show all supported endpoints and their parameters (see official documentation for detail)
        """
        return self._get("/endpoints")

    def license(self):
        """
        show license info; currently returns an error (not useful)
        """
        return self._get("/showlicenseinfo")

    def stat(self, graph, **kwargs):
        """
        used for calling stat functions. (see official documentation for detail)

        commonly used stat functions are separate methods:
          1. stat_vertex_number
          2. stat_edge_number
          3. stat_vertex_attr
          4. stat_edge_attr
        """
        url = "/builtins/" + graph
        return self._post(url, content=json.dumps(kwargs, ensure_ascii=True))

    def stat_vertex_number(self, graph, type_name="*"):
        return self.stat(graph, function="stat_vertex_number", type=type_name)

    def stat_edge_number(self, graph, type_name="*", from_type_name="*", to_type_name="*"):
        return self.stat(graph, function="stat_edge_number", type=type_name,
                         from_type=from_type_name, to_type=to_type_name)

    def stat_vertex_attr(self, graph, type_name="*"):
        return self.stat(graph, function="stat_vertex_attr", type=type_name)

    def stat_edge_attr(self, graph, type_name="*", from_type_name="*", to_type_name="*"):
        return self.stat(graph, function="stat_edge_attr", type=type_name,
                         from_type=from_type_name, to_type=to_type_name)

    def select_vertices(self, graph, vertex_type, vertex_id=None, **kwargs):
        """
        kwargs:
            select: attr1,attr2; -attr1,-attr2; -_
            filter: attr1>30,attr2<=50,...
            limit: 10
            sort: attr1,-attr2
            timeout: 0 in seconds
        """
        endpoint = "/graph/{0}/vertices/{1}".format(graph, vertex_type)
        if vertex_id:
            endpoint += "/" + vertex_id
        return self._get(endpoint, kwargs)

    def select_edges(self, graph, src_type, src_id, edge_type="_", dst_type=None, dst_id=None, **kwargs):
        """
        kwargs:
            select: attr1,attr2; -attr1,-attr2; -_
            filter: attr1>30,attr2<=50,...
            limit: 10
            sort: attr1,-attr2
            timeout: 0 in seconds
        """
        endpoint = "/graph/{0}/edges/{1}/{2}/{3}".format(graph, src_type, src_id, edge_type)
        if dst_type:
            endpoint += "/" + dst_type
            if dst_id:
                endpoint += "/" + dst_id
        return self._get(endpoint, kwargs)

    def delete_vertices(self, graph, vertex_type, vertex_id=None, **kwargs):
        """
        kwargs:
            filter: attr1>30,attr2<=50,...
            limit: 10
            sort: attr1,-attr2
            timeout: 0 in seconds
        """
        endpoint = "/graph/{0}/vertices/{1}".format(graph, vertex_type)
        if vertex_id:
            endpoint += "/" + vertex_id
        return self._get(endpoint, kwargs)

    def delete_edges(self, graph, src_type, src_id, edge_type="_", dst_type=None, dst_id=None, **kwargs):
        """
        kwargs:
            filter: attr1>30,attr2<=50,...
            limit: 10
            sort: attr1,-attr2
            timeout: 0 in seconds
        """
        endpoint = "/graph/{0}/edges/{1}/{2}/{3}".format(graph, src_type, src_id, edge_type)
        if dst_type:
            endpoint += "/" + dst_type
            if dst_id:
                endpoint += "/" + dst_id
        return self._delete(endpoint, kwargs)

    def load(self, graph, lines, **kwargs):
        """
        load data to graph

        graph: graph name
        lines: list of json string/csv lines

        required:
            tag: load job name
            filename: file parameter name or file path
        optional:
            sep: default ","
            ack: default "all", choose "all" or "none"
            timeout: default 0, seconds
        """
        if lines:
            content = "\n".join(lines)
        else:
            content = None

        endpoint = "/ddl/" + graph
        return self._post(endpoint, kwargs, content)

    def update(self, graph, content):
        """
        content is json like:
            vertices: vertex_type: vertex_id: attribute: {value, op}
            edges: src_vertex_type: src_vertex_id: edge_type: dst_vertex_type: dst_vertex_id: attribute: {value, op}
        """
        return self._post("/graph/" + graph, content=json.dumps(content, ensure_ascii=True))

    def query(self, graph, query_name, **kwargs):
        """
        run a specific query
        """
        return self._get("/{0}/{1}".format(graph, query_name), kwargs)
