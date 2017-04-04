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
OAUTH_ACCESS_TOKEN_URL = "https://okpy.org/oauth/token"
OAUTH_AUTHORIZE_URL =  "https://okpy.org/oauth/authorize"

class OkpyMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = OAUTH_AUTHORIZE_URL
    _OAUTH_ACCESS_TOKEN_URL = OAUTH_ACCESS_TOKEN_URL

class OkpyLoginHandler(OAuthLoginHandler, OkpyMixin):
    pass

class OkpyCallbackHandler(BaseHandler):
    """Basic handler for Okpy callback.
    Calls authenticator to verify username. Then it sets the state in the env var.
    """
    @gen.coroutine
    def get(self):
        # TODO: Check if state argument needs to be checked
        username, state = yield self.authenticator.authenticate(self, None)

        if username:
            user = self.user_from_username(username)
            user.auth_state = state
            self.db.add(user)
            self.db.commit()
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)

class OkpyOAuthenticator(OAuthenticator):
    login_service = "okpy"
    callback_handler = OkpyCallbackHandler
    login_handler = OkpyLoginHandler
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "Authentication Failed.")
        http_client = AsyncHTTPClient()
        params = dict(
            redirect_uri = "http://localhost:8000/hub/oauth_callback",
            code=code,
            grant_type='authorization_code'
        )
        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )
        url = url_concat(OAUTH_ACCESS_TOKEN_URL, params)
        req = HTTPRequest(url,
                          method = "POST",
                          headers = {"Accept": "application/json",
                                     "User-Agent": "JupyterHub",
                                     "Authorization": "Basic {}".format(b64key.decode("utf8"))},
                          body = '' # Body is required for a POST...
                          )
        resp = yield http_client.fetch(req)
        state = json.loads(resp.body.decode('utf8', 'replace'))
        access_token = state['access_token']
        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)}
        url = url_concat(OKPY_USER_URL, {"envelope" : "false"})
        req = HTTPRequest(url, method="GET", headers=headers)
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        print(resp_json)
        return resp_json["email"], state

class LocalOkpyOAuthenticator(LocalAuthenticator, OkpyOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
