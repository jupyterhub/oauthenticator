"""
Custom Authenticator to use okpy OAuth with JupyterHub
"""
import json
import os
import base64

from tornado.auth import OAuth2Mixin
from tornado import gen, web


from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

OKPY_USER_URL = "https://okpy.org/api/v3/user"

class OkpyLoginHandler(OAuthLoginHandler, OAuth2Mixin):
    """ An OAuthLoginHandler that provides scope to
        OkpyMixin's authorize_redirect.
    """
    _OAUTH_ACCESS_TOKEN_URL = "https://okpy.org/oauth/token"
    _OAUTH_AUTHORIZE_URL =  "https://okpy.org/oauth/authorize"
    def get(self):
        self.authorize_redirect(
            redirect_uri = self.authenticator.oauth_callback_url,
            client_id = self.authenticator.client_id,
            scope= ['all'],
            response_type = 'code')

class OkpyCallbackHandler(BaseHandler, OAuth2Mixin):
    """ Basic handler for Okpy callback.
        Calls authenticator to verify user and saves the state in user.
    """
    def get_auth_request(self, code):
        params = dict(
            redirect_uri = self.authenticator.oauth_callback_url,
            code = code,
            grant_type = 'authorization_code'
        )
        b64key = base64.b64encode(
            bytes("{}:{}".format(self.authenticator.client_id,
                                 self.authenticator.client_secret), "utf8"
                 )
        )
        url = url_concat(OAUTH_ACCESS_TOKEN_URL, params)
        req = HTTPRequest(url,
                method = "POST",
                headers = { "Accept": "application/json",
                            "User-Agent": "JupyterHub",
                            "Authorization": "Basic {}".format(b64key.decode("utf8"))},
                            body = '' # Body is required for a POST...
                          )
        return req

    @gen.coroutine
    def get(self):
        username, state = yield self.authenticator.authenticate(self, None)
        if username:
            user = self.user_from_username(username)
            user.auth_state = state
            self.db.add(user)
            self.db.commit()
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            raise web.HTTPError(403, "Authentication Failed.")

    def get_user_info_request(self, access_token):
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)}
        params = {"envelope" : "false"}
        url = url_concat(OKPY_USER_URL, params)
        req = HTTPRequest(url, method = "GET", headers = headers)
        return req

class OkpyOAuthenticator(OAuthenticator, OAuth2Mixin):
    login_service = "Okpy"
    callback_handler = OkpyCallbackHandler
    login_handler = OkpyLoginHandler
    @gen.coroutine
    def authenticate(self, handler, data = None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "Authentication Cancelled.")
        http_client = AsyncHTTPClient()
        auth_request = handler.get_auth_request(code)
        response = yield http_client.fetch(auth_request)
        if not response:
            self.clear_all_cookies()
            raise HTTPError(500, 'Authentication Failed: Token Not Acquired')
        state = json.loads(response.body.decode('utf8', 'replace'))
        access_token = state['access_token']
        info_request = handler.get_user_info_request(access_token)
        response = yield http_client.fetch(info_request)
        user = json.loads(response.body.decode('utf8', 'replace'))
        return user["email"], state

class LocalOkpyOAuthenticator(LocalAuthenticator, OkpyOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
