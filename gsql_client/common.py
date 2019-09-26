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
