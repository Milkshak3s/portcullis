from functools import wraps
from flask import request, make_response, session
from flask_httpauth import HTTPBasicAuth
import requests


class PortcullisAuth():

    """
    Class for managing authentication to 
    a Portcullis server
    """

    def __init__(self):
        """
        Init for the PortcullisAuth object, for wrappers!
        """
        self.portcullis_server = "localhost"
        self.portcullis_port = 80

        self._request_server = "http://" + self.portcullis_server + \
                              ":" + str(self.portcullis_port)

        self._auth_path_rec = "/port/auth/resource"
        self._auth_path_perm = "/port/auth/permission"

    def recauth(self, f):
        """
        Check if the auth'd user has access to the resource path requested
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if auth_header is None:
                # if there's no Auth header, they're not using a token
                return {'error': 'missing auth token'}

            url = self._request_server + self._auth_path_rec
            headers = {'Authorization': auth_header}
            payload = {'resource_path': request.path}
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

        return decorated