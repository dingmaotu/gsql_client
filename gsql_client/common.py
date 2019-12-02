# -*- coding: utf-8 -*-

"""
Common imports and exceptions
"""

# import http client
try:
    # noinspection PyCompatibility
    from urllib.parse import quote_plus, urlencode
    # noinspection PyCompatibility
    from http.client import HTTPConnection, HTTPSConnection


    def native_str(s):
        return s


    def is_str(s):
        return isinstance(s, str)

except ImportError:
    from urllib import quote_plus, urlencode
    # noinspection PyCompatibility
    from httplib import HTTPConnection, HTTPSConnection


    def native_str(s):
        if isinstance(s, unicode):
            return s.encode("utf-8")
        else:  # str or other: native str does not handle non string types
            return s


    def is_str(s):
        return isinstance(s, (str, unicode))

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
