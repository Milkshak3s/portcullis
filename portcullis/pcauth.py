from functools import wraps
from flask import request, make_response, session
from flask_httpauth import HTTPBasicAuth
import requests


class PortcullisAuth():

    """
    Class for managing authentication to 
    a Portcullis server
    """

    def __init__(self, server, port, ssl=False):
        """
        Init for the PortcullisAuth object, for wrappers!
        """
        self._portcullis_server = server
        self._portcullis_port = port

        if ssl:
            self._request_server = "https://" + self._portcullis_server + \
                                   ":" + str(self._portcullis_port)
        else:
            self._request_server = "http://" + self._portcullis_server + \
                                   ":" + str(self._portcullis_port)

        self._auth_path_rec = "/port/auth/resource"
        self._auth_path_perm = "/port/auth/permission"

    def recauth(self, recpath=None):
        """
        Check if the auth'd user has access to the resource path requested
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                recpath_inner = recpath
                if recpath_inner is None:
                    # if a resource path isn't specified, use path in request
                    recpath_inner = request.path

                auth_header = request.headers.get('Authorization')
                if auth_header is None:
                    # if there's no Auth header, they're not using a token
                    return {'error': 'missing auth token'}

                url = self._request_server + self._auth_path_rec
                headers = {'Authorization': auth_header}
                payload = {'resource_path': recpath_inner}
                response = requests.request("POST", url, json=payload, headers=headers)

                try:
                    r_data = response.json()
                except:
                    # probably unauthed access or internal server error
                    return {'error': 'unexpected response from auth server'}

                has_access = r_data.get('has_access')
                if has_access is False:
                    # auth server returned False
                    return {'error': 'bad permissions'}
                elif has_access is None:
                    # auth server returned an error probably
                    return {'error': 'unexpected response from auth server'}

                # at this point, success!
                return f(*args, **kwargs)

            return decorated_function

        return decorator

    def permauth(self, perm=None):
        """
        Check if the auth'd user has access to the permission specified
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if perm is None:
                    return {'error': 'no permission specified'}

                auth_header = request.headers.get('Authorization')
                if auth_header is None:
                    # if there's no Auth header, they're not using a token
                    return {'error': 'missing auth token'}

                url = self._request_server + self._auth_path_perm
                headers = {'Authorization': auth_header}
                payload = {'perm_name': perm}
                response = requests.request("POST", url, json=payload, headers=headers)

                try:
                    r_data = response.json()
                except:
                    # probably unauthed access or internal server error
                    return {'error': 'unexpected response from auth server'}

                has_access = r_data.get('has_access')
                if has_access is False:
                    # auth server returned False
                    return {'error': 'bad permissions'}
                elif has_access is None:
                    # auth server returned an error probably
                    return {'error': 'unexpected response from auth server'}

                # at this point, success!
                return f(*args, **kwargs)

            return decorated_function

        return decorator
