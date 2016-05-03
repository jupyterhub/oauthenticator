"""
Custom Authenticator to use HydroShare OAuth with JupyterHub

"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict

from .oauth2 import OAuthLoginHandler, OAuthenticator

class HydroShareMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = 'https://www.hydroshare.org/o/authorize'
    _OAUTH_ACCESS_TOKEN_URL = 'https://www.hydroshare.org/o/token'


class HydroShareLoginHandler(OAuthLoginHandler, HydroShareMixin):
    pass


class HydroShareOAuthenticator(OAuthenticator):

    login_service = "HydroShare"

    client_id_env = 'HYDROSHARE_CLIENT_ID'
    client_secret_env = 'HYDROSHARE_CLIENT_SECRET'
    login_handler = HydroShareLoginHandler

    username_map = Dict(config=True, default_value={},
                        help="""Optional dict to remap github usernames to nix usernames.
        """)

    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        self.log.info('code: ' + code)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")

        http_client = AsyncHTTPClient()

        # POST request parameters for HydroShare  
        params = dict(
            grant_type='authorization_code',
            code=code,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.oauth_callback_url,
        )

        url = url_concat(
                        'https://www.hydroshare.org/o/token/',
                         params)
        self.log.info(url)

        self.log.info('url: '+str(url))

        req = HTTPRequest(url,method="POST",body='', headers={"Accept": "application/json"}, validate_cert=False,)

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        self.log.info('RESPONSE_JSON: '+str(resp_json))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("https://hydroshare.org/hsapi/userInfo",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        self.log.info('user: '+str(resp_json))
        
        # get the username variable from the response
        hs_username = resp_json["username"]
        
        # remap hydroshare username to system username
        nix_username = self.username_map.get(hs_username, hs_username)
        
        #check system username against whitelist
        use_whitelist = os.environ('HYDROSHARE_USE_WHITELIST') or True
        if use_whitelist:
            if self.whitelist and nix_username not in self.whitelist:
                self.log.error('Username not in whitelist: %s' % nix_username)
                nix_username = None
        return nix_username


class LocalHydroShareOAuthenticator(LocalAuthenticator, HydroShareOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
