from functools import wraps
from flask import request, make_response, session
from flask_httpauth import HTTPBasicAuth


class PortcullisAuth():

    """
    Class for managing authentication to 
    a Portcullis server
    """

    def __init__(self):
        self.portcullis_server = "localhost"
        self.portcullis_port = 80

        self._auth_path_obj = "/port/auth/resource"
        self._auth_path_perm = "/port/auth/permission"

    def check_obj_auth(self, req_path):
        """
        Check if the auth'd user has access to the path requested
        """

    def objauth(self, f):
        """
        Check if the auth'd user has access to the path requested
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            print(auth)

            return f(*args, **kwargs)

        return decorated