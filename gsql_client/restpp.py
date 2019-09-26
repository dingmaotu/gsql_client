# -*- coding: utf-8 -*-

"""
RESTPP Client
"""

# for python 2 and 3 compatibility, we import these anyway
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

import json
import logging

from .common import HTTPConnection, urlencode, AuthenticationFailedException


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

        self._logger = logging.getLogger("gsql_client.restpp.RESTPP")

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
            elif "token" in res:
                return res["token"]
            elif "results" in res:
                return res["results"]
            elif "message" in res:
                return res["message"]
            else:
                return res
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