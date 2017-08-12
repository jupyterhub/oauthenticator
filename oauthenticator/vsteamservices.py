"""
Custom Authenticator to use Visual Studio Team Service OAuth with JupyterHub

"""

import json
import os
import urllib

from jupyterhub.auth import LocalAuthenticator
from tornado import gen
from tornado.auth import OAuth2Mixin
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.httputil import url_concat

from .oauth2 import OAuthLoginHandler, OAuthenticator

VSTS_HOST = os.environ.get('VSTS_HOST') or 'app.vssps.visualstudio.com'


class VstsEnvMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/oauth2/authorize" % VSTS_HOST
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/oauth2/token" % VSTS_HOST


class VstsLoginHandler(OAuthLoginHandler, VstsEnvMixin):
    scope = ["vso.profile"]

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        self.log.info('VSTS redirect: %r', redirect_uri)
        state = self.get_state()
        self.set_state_cookie(state)
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=self.scope,
            extra_params={'state': state},
            response_type='Assertion')


class VstsOAuthenticator(OAuthenticator):
    login_service = "Visual Studio Team Services"

    client_id_env = 'VSTS_CLIENT_ID'
    client_secret_env = 'VSTS_CLIENT_SECRET'
    login_handler = VstsLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a Visual Studio Team Services Access Token
        #
        # See: https://www.visualstudio.com/en-us/docs/integrate/get-started/authentication/oauth

        params = dict(
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=self.client_secret,
            grant_type='urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion=code,
            redirect_uri=self.get_callback_url(handler)
        )

        url = "https://%s/oauth2/token" % VSTS_HOST

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "JupyterHub"
        }
        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          body=urllib.parse.urlencode(params)
                          # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        token_type = resp_json['token_type']

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {0}".format(access_token)
        }
        url = url_concat("https://%s/_apis/profile/profiles/me" % VSTS_HOST, {
            "api_version": "1.0"
        })

        req = HTTPRequest(url,
                          method="GET",
                          headers=headers,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if resp_json.get("emailAddress"):
            return resp_json["emailAddress"]


class LocalVstsOAuthenticator(LocalAuthenticator, VstsOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
