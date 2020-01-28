"""
Custom Authenticator to use okpy OAuth with JupyterHub
"""
import json
from binascii import a2b_base64

from tornado.auth import OAuth2Mixin
from tornado import web
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.httputil import url_concat
from traitlets import default

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthenticator


class OkpyOAuthenticator(OAuthenticator, OAuth2Mixin):
    login_service = "OK"

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://okpy.org/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return "https://okpy.org/oauth/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return "https://okpy.org/api/v3/user"

    @default('scope')
    def _default_scope(self):
        return ['email']

    def get_auth_request(self, code):
        params = dict(
            redirect_uri=self.oauth_callback_url,
            code=code,
            grant_type='authorization_code',
        )
        b64key = a2b_base64("{}:{}".format(self.client_id, self.client_secret)).decode(
            'ascii'
        )
        url = url_concat(self.token_url, params)
        req = HTTPRequest(
            url,
            method="POST",
            headers={
                "Accept": "application/json",
                "User-Agent": "JupyterHub",
                "Authorization": "Basic {}".format(b64key),
            },
            body='',  # Body is required for a POST...
        )
        return req

    def get_user_info_request(self, access_token):
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token),
        }
        params = {"envelope": "false"}
        url = url_concat(self.userdata_url, params)
        req = HTTPRequest(url, method="GET", headers=headers)
        return req

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "Authentication Cancelled.")
        http_client = AsyncHTTPClient()
        auth_request = self.get_auth_request(code)
        response = await http_client.fetch(auth_request)
        if not response:
            raise web.HTTPError(500, 'Authentication Failed: Token Not Acquired')
        state = json.loads(response.body.decode('utf8', 'replace'))
        access_token = state['access_token']
        info_request = self.get_user_info_request(access_token)
        response = await http_client.fetch(info_request)
        user = json.loads(response.body.decode('utf8', 'replace'))
        # TODO: preserve state in auth_state when JupyterHub supports encrypted auth_state
        return {
            'name': user['email'],
            'auth_state': {'access_token': access_token, 'okpy_user': user},
        }


class LocalOkpyOAuthenticator(LocalAuthenticator, OkpyOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
