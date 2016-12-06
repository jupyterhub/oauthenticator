"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""


import json
import os
import base64

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .base import OAuthLoginHandler, OAuthenticator


class OAuth2Config(object):
    token_url = Unicode(
        os.environ.get('OAUTH2_AUTHORIZE_URL', ''),
        config=True,
        help="Authorize url for OAuth2"
    )
    authorize_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help="Token url for OAuth2"
    )
    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL', ''),
        config=True,
        help="Userdata url to get user data login information"
    )
    userlogin_key = Unicode(
        os.environ.get('OAUTH2_USERLOGIN_KEY', 'login'),
        config=True,
        help="Userdata login key from returned json for USERDATA_URL"
    )
    userdata_params = Unicode(
        os.environ.get('OAUTH2_USERDATA_PARAMS', {}),
        config=True,
        help="Userdata params to get user data login information"
    )
    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information"
    )


class OAuth2EnvMixin(OAuth2Mixin, OAuth2Config):
    _OAUTH_AUTHORIZE_URL = token_url
    _OAUTH_ACCESS_TOKEN_URL = authorize_url


class OAuth2LoginHandler(OAuthLoginHandler, OAuth2EnvMixin):
    pass


class OAuth2OAuthenticator(OAuthenticator, OAuth2Config):

    login_service = "OAuth2"

    client_id_env = 'OAUTH2_CLIENT_ID'
    client_secret_env = 'OAUTH2_CLIENT_SECRET'
    login_handler = OAuth2LoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=os.environ.get(self.oauth_callback_url,
            code=code,
            grant_type='authorization_code'
        )

        url = url_concat(self.token_url, params)

        b64key = base64.b64encode("{}:{}".format(self.client_id, self.client_secret))

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key)
        }

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          body='' # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }
        url = url_concat(self.userdata_url, self.userdata_params)

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json.get(self.userlogin_key)


class LocalOAuth2OAuthenticator(LocalAuthenticator, OAuth2OAuthenticator):

    """A version that mixes in local system user creation"""
    pass
