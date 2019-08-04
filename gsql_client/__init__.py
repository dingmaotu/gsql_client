# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

import sys
import re
import io
import copy
from os import getenv
from os.path import expanduser, isfile

if sys.version_info.major == 2:
    is_legacy = True
    from urllib2 import urlopen, Request
    from urllib import urlencode
    from urllib2 import URLError
    from httplib import IncompleteRead
else:
    is_legacy = False
    from urllib.request import urlopen, Request
    from urllib.parse import urlencode
    from urllib.error import URLError
    from http.client import IncompleteRead

try:
    import ssl
except ImportError:
    HAS_SSL = False
else:
    HAS_SSL = True

import base64
import json
import logging


class LoginException(Exception):
    pass


class InvalidPasswordException(Exception):
    pass


class MalformedRequestOrConnectionException(Exception):
    pass


class RecursiveIncludeException(Exception):
    pass


class ReturnCodeException(Exception):
    pass


MSG_CONNECTION_REFUSED = """Connection refused.
Please check the status of GSQL server using "gadmin status gsql".
If it's down, please start it on server first by "gadmin start gsql".
If you are on a client machine and haven't configured the GSQL server IP address yet,
please create a file called gsql_server_ip_config in the same directory as 
gsql_client.jar, containing one item: the GSQL server IP, e.g. 192.168.1.1
Please also make sure the versions of the client and the server are the same."""

PREFIX_CURSOR_UP = "__GSQL__MOVE__CURSOR___UP__"
PREFIX_CLEAN_LINE = "__GSQL__CLEAN__LINE__"
PREFIX_INTERACT = "__GSQL__INTERACT__"
PREFIX_RET = "__GSQL__RETURN__CODE__"
PREFIX_COOKIE = "__GSQL__COOKIES__"

FILE_PATTERN = re.compile("@[^@]*[^;,]")
PROGRESS_PATTERN = re.compile("\\[=*\\s*\\]\\s[0-9]+%.*")
COMPLETE_PATTERN = re.compile("\\[=*\\s*\\]\\s100%[^l]*")


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
        self.logger = logging.getLogger(__name__)
        self.server_ip = server_ip
        self.username = username
        self.password = password

        if cacert and HAS_SSL:
            self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_verify_locations(cacert)
            self.protocol = "https"
        else:
            self.context = None
            self.protocol = "http"

        self.base64_credential = base64.b64encode(
            "{0}:{1}".format(self.username, self.password).encode("utf-8")).decode("utf-8")

        self.is_local = server_ip.startswith("127.0.0.1") or server_ip.startswith("localhost")

        if self.is_local:
            if ":" not in server_ip:
                port = get_option("gsql.server.private_port", "8123")
                self.base_url = "{0}://{1}:{2}/gsql/".format(self.protocol, server_ip, port)
            else:
                self.base_url = "{0}://{1}/gsql".format(self.protocol, server_ip)

        else:
            if ":" not in server_ip:
                self.base_url = "{0}://{1}:{2}/gsqlserver/gsql/".format(self.protocol, server_ip, "14240")
            else:
                self.base_url = "{0}://{1}/gsql/gsqlserver/gsql/".format(self.protocol, server_ip)

        # check not malformed url

        self._initialize_url()

        self.graph = ""
        self.session = ""
        self.properties = ""

        self.authorization = 'Basic {0}'.format(self.base64_credential)

        self.logger.debug("base url: {0}".format(self.base_url))
        self.logger.debug("User: {0}:{1}".format(self.username, self.password))
        self.logger.debug("User Encoded: {0}".format(self.base64_credential))

    def _initialize_url(self):
        self.command_url = self.base_url + "command"
        self.version_url = self.base_url + "version"
        self.help_url = self.base_url + "help"
        self.login_url = self.base_url + "login"
        self.reset_url = self.base_url + "reset"
        self.file_url = self.base_url + "file"
        self.dialog_url = self.base_url + "dialog"

        self.info_url = self.base_url + "getinfo"
        self.abort_url = self.base_url + "abortloadingprogress"

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

    def _setup_request(self, url, content, headers):
        encoded = content.encode("utf-8")
        headers = copy.deepcopy(headers)
        headers["Content-Language"] = "en-US"
        headers["Content-Length"] = str(len(encoded))
        headers["Pragma"] = "no-cache"

        # default is POST if we have content
        # deafult Content-Type is application/x-www-form-urlencoded
        return Request(url, encoded, headers)

    def load_file_recursively(self, file_path):
        return self._read_file(file_path, set())

    def _read_file(self, file_path, loaded):
        if not file_path or not isfile(file_path):
            self.logger.warn("File \"" + file_path + "\" does not exist!")
            return ""

        if file_path in loaded:
            self.logger.error("There is an endless loop by using @" + file_path + " cmd recursively.")
            raise RecursiveIncludeException(file_path)
        else:
            loaded.add(file_path)

        res = ""
        with io.open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if FILE_PATTERN.match(line):
                    res += self.read_file(line[1:], loaded) + "\n"
                    continue
                res += line + "\n"

        return res

    def _call(self, url, content):
        """get response as text"""
        r = self._setup_request(url, content, {"Authorization": self.authorization, "Cookie": self.session})
        response = None
        try:
            response = urlopen(r)
            ret_code = response.getcode()
            if ret_code == 401:
                self.logger.error("Authentication failed.")
                return None
            if ret_code != 200:
                error_info = "Connection Error.\nResponse Code : " + ret_code + "\n" + urlencode(content) + "\n"
                self.logger.error(error_info)
                return None
            content = response.read()
            return content.decode("utf-8")
        except URLError:
            self.logger.error(MSG_CONNECTION_REFUSED)
        except Exception:
            self.logger.exception("error when connecting to gsql server")
        finally:
            if response:
                response.close()

    def _command(self, url, content):
        """just send the content without expecting response"""
        r = self._setup_request(url, content, {"Authorization": self.authorization, "Cookie": self._get_cookie()})
        response = None
        try:
            response = urlopen(r)
            ret_code = response.getcode()
            if ret_code == 401:
                self.logger.error("Authentication failed.")
        except URLError:
            self.logger.error(MSG_CONNECTION_REFUSED)
        except Exception:
            self.logger.exception("error when connecting to gsql server")
        finally:
            if response:
                response.close()

    def _dialog(self, response):
        self._command(self.dialog_url, response)

    def _command_interactive(self, url, content, ans=""):
        """process response with special return codes"""
        r = self._setup_request(url, content, {"Authorization": self.authorization, "Cookie": self._get_cookie()})
        response = None
        try:
            response = urlopen(r)
            ret_code = response.getcode()
            if ret_code == 401:
                self.logger.error("Authentication failed.")
                return None
            if ret_code != 200:
                error_info = "Connection Error.\nResponse Code : " + ret_code + "\n" + urlencode(content) + "\n"
                self.logger.error(error_info)
                return None
            res = []
            for raw_line in response:
                line = raw_line.decode("utf-8").strip()
                if line.startswith(PREFIX_RET):
                    _, ret = line.split(",", 1)
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
                    print(line)
                    res.append(line)
            return "\n".join(res)
        except URLError:
            self.logger.error(MSG_CONNECTION_REFUSED)
        except IncompleteRead as icr:
            self.logger.error("read incomplete:")
            self.logger.error(icr.partial)
        except Exception:
            self.logger.exception("error when connecting to gsql server")
        finally:
            if response:
                response.close()

    def login(self):
        r = self._setup_request(self.login_url, self.base64_credential, {"Cookie": self._get_cookie()})
        response = None
        try:
            response = urlopen(r)
            ret_code = response.getcode()
            if ret_code == 200:
                content = response.read()
                res = json.loads(content.decode("utf-8"))

                if res.get("error", False):
                    if "Wrong password!" in res.get("message", ""):
                        raise InvalidPasswordException()
                else:
                    messages = response.info()
                    self.session = messages["Set-Cookie"]
                    return True
            else:
                raise LoginException("Error while login!")
        except URLError:
            self.logger.error(MSG_CONNECTION_REFUSED)
        except Exception:
            self.logger.exception("error when connecting to gsql server")
        finally:
            if response:
                response.close()

    def get_auto_keys(self):
        keys = self._call(self.info_url, "autokeys")
        return keys.split(",")

    def quit(self):
        self._command(self.abort_url, "abortloadingprogress")

    def command(self, content, ans=""):
        return self._command_interactive(self.command_url, content, ans)

    def file(self, path):
        content = self.load_file_recursively(path)
        return self._command_interactive(self.file_url, content)

    def version(self):
        return self._command_interactive(self.version_url, "version")

    def help(self):
        return self._command_interactive(self.help_url, "help")
