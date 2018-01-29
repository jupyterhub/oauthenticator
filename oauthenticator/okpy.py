"""
Custom Authenticator to use okpy OAuth with JupyterHub
"""
import json
from binascii import a2b_base64

from tornado.auth import OAuth2Mixin
from tornado import gen, web
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.httputil import url_concat
from traitlets import default

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator

OKPY_USER_URL = "https://okpy.org/api/v3/user"
OKPY_ACCESS_TOKEN_URL = "https://okpy.org/oauth/token"
OKPY_AUTHORIZE_URL =  "https://okpy.org/oauth/authorize"


class OkpyMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = OKPY_ACCESS_TOKEN_URL
    _OAUTH_AUTHORIZE_URL = OKPY_AUTHORIZE_URL


class OkpyLoginHandler(OAuthLoginHandler, OkpyMixin):
    pass


class OkpyOAuthenticator(OAuthenticator, OAuth2Mixin):
    login_service = "Okpy"
    login_handler = OkpyLoginHandler
    
    @default('scope')
    def _default_scope(self):
        return ['email']

    def get_auth_request(self, code):
        params = dict(
            redirect_uri = self.oauth_callback_url,
            code = code,
            grant_type = 'authorization_code'
        )
        b64key = a2b_base64("{}:{}".format(self.client_id, self.client_secret)).decode('ascii')
        url = url_concat(OKPY_ACCESS_TOKEN_URL, params)
        req = HTTPRequest(url,
                method = "POST",
                headers = { "Accept": "application/json",
                            "User-Agent": "JupyterHub",
                            "Authorization": "Basic {}".format(b64key),
                          },
                body = '' # Body is required for a POST...
        )
        return req

    def get_user_info_request(self, access_token):
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)}
        params = {"envelope" : "false"}
        url = url_concat(OKPY_USER_URL, params)
        req = HTTPRequest(url, method = "GET", headers = headers)
        return req

    @gen.coroutine
    def authenticate(self, handler, data = None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "Authentication Cancelled.")
        http_client = AsyncHTTPClient()
        auth_request = self.get_auth_request(code)
        response = yield http_client.fetch(auth_request)
        if not response:
            raise web.HTTPError(500, 'Authentication Failed: Token Not Acquired')
        state = json.loads(response.body.decode('utf8', 'replace'))
        access_token = state['access_token']
        info_request = self.get_user_info_request(access_token)
        response = yield http_client.fetch(info_request)
        user = json.loads(response.body.decode('utf8', 'replace'))
        # TODO: preserve state in auth_state when JupyterHub supports encrypted auth_state
        return {
            'name': user['email'],
            'auth_state': {
                'access_token': access_token,
                'okpy_user': user,
            }
        }

class LocalOkpyOAuthenticator(LocalAuthenticator, OkpyOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
