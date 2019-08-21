# -*- coding: utf-8 -*-

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

try:
    # noinspection PyCompatibility
    from urllib.parse import quote_plus, urlencode
    # noinspection PyCompatibility
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from urllib import quote_plus, urlencode
    # noinspection PyCompatibility
    from httplib import HTTPConnection, HTTPSConnection

try:
    # noinspection PyUnresolvedReferences
    import ssl

    HAS_SSL = True
except ImportError:
    HAS_SSL = False


class AuthenticationFailedException(Exception):
    pass


class RecursiveIncludeException(Exception):
    pass


class ReturnCodeException(Exception):
    pass


PREFIX_CURSOR_UP = "__GSQL__MOVE__CURSOR___UP__"
PREFIX_CLEAN_LINE = "__GSQL__CLEAN__LINE__"
PREFIX_INTERACT = "__GSQL__INTERACT__"
PREFIX_RET = "__GSQL__RETURN__CODE__"
PREFIX_COOKIE = "__GSQL__COOKIES__"

FILE_PATTERN = re.compile("@[^@]*[^;,]")
PROGRESS_PATTERN = re.compile("\\[=*\\s*\\]\\s[0-9]+%.*")
COMPLETE_PATTERN = re.compile("\\[=*\\s*\\]\\s100%[^l]*")

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
    return line.endswith(":")


def _get_current_mode(line):
    return CATALOG_MODES.get(line[:-1], NULL_MODE)


def _parse_catalog(lines):
    """
    parse output of ls
    return a dict of:
        vertices: []
        edges: []
        graphs: []
        jobs: []
        queries: []
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
    cfg_path = expanduser("~/.gsql/gsql.cfg")
    with open(cfg_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith(option):
                values = line.split()
                if len(values) >= 2:
                    return values[1]
    return default


class Client(object):
    """
    Main class of the client lib
    """

    def __init__(self, server_ip="127.0.0.1", username="tigergraph", password="tigergraph", cacert=""):
        """
        Create a client from remote server ip, username, and password
        """
        self._logger = logging.getLogger("gsql_client.Client")
        self._server_ip = server_ip
        self._username = username
        self._password = password

        if cacert and HAS_SSL:
            self._context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_REQUIRED
            self._context.load_verify_locations(cacert)
            self._protocol = "https"
        else:
            self._context = None
            self._protocol = "http"

        self.base64_credential = base64.b64encode(
            "{0}:{1}".format(self._username, self._password).encode("utf-8")).decode("utf-8")

        self.is_local = server_ip.startswith("127.0.0.1") or server_ip.startswith("localhost")

        if self.is_local:
            self._base_url = "/gsql/"
            if ":" not in server_ip:
                port = get_option("gsql.server.private_port", "8123")
                self._server_ip = "{0}:{1}".format(server_ip, port)

        else:
            self._base_url = "/gsqlserver/gsql/"
            if ":" not in server_ip:
                self._server_ip = "{0}:{1}".format(server_ip, "14240")

        self._initialize_url()

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
        self.abort_url = self._base_url + "abortloadingprogress"

    def _get_cookie(self):
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

        return json.dumps(cookie, ensure_ascii=True)

    def _set_cookie(self, cookie_str):
        cookie = json.loads(cookie_str)
        self.session = cookie.get("session", "")
        self.graph = cookie.get("graph", "")
        self.properties = cookie.get("properties", "")

    def _setup_connection(self, url, content, cookie=None, auth=True):
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
        self._request(self.dialog_url, response)

    def _command_interactive(self, url, content, ans="", out=True):
        """process response with special return codes"""

        def __handle__interactive(reader):
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
        response = None
        try:
            r = self._setup_connection(self.login_url, self.base64_credential, auth=False)
            response = r.getresponse()
            ret_code = response.status
            if ret_code == 200:
                content = response.read()
                res = json.loads(content.decode("utf-8"))

                if res.get("error", False):
                    if "Wrong password!" in res.get("message", ""):
                        raise AuthenticationFailedException("Invalid Username/Password!")
                else:
                    self.session = response.getheader("Set-Cookie")
                    return True
        finally:
            if response:
                response.close()

    def get_auto_keys(self):
        keys = self._request(self.info_url, "autokeys", cookie=self.session)
        return keys.split(",")

    def quit(self):
        self._request(self.abort_url, "abortloadingprogress")

    def command(self, content, ans=""):
        return self._command_interactive(self.command_url, content, ans)

    def use(self, graph):
        return self._command_interactive(self.command_url, "use graph {0}".format(graph))

    def catalog(self):
        lines = self._command_interactive(self.command_url, "ls", out=False)
        return _parse_catalog(lines)

    def _load_file_recursively(self, file_path):
        return self._read_file(file_path, set())

    def _read_file(self, file_path, loaded):
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
        content = self._load_file_recursively(path)
        return self._command_interactive(self.file_url, content)

    def run_multiple(self, lines):
        return self._command_interactive(self.file_url, "\n".join(lines))

    def version(self):
        return self._command_interactive(self.version_url, "version")

    def help(self):
        return self._command_interactive(self.help_url, "help")


class RESTPPError(Exception):
    pass


class RESTPP(object):
    def __init__(self, server_ip):
        self._token = ""
        if ":" in server_ip:
            self._server_ip = server_ip
        else:
            self._server_ip = server_ip + ":9000"

        self._logger = logging.getLogger("gsql_client.RESTPP")

    def _setup_connection(self, method, endpoint, parameters, content):
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
        return self._get("/echo")

    def version(self):
        return self._get("/version")

    def endpoints(self):
        return self._get("/endpoints")

    def license(self):
        return self._get("/showlicenseinfo")

    def stat(self, graph, **kwargs):
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
        lines: list of json string

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
        return self._get("/{0}/{1}".format(graph, query_name), kwargs)
