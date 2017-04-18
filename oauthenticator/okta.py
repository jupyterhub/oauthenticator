"""
Custom Authenticator to use Okta OAuth with JupyterHub

Derived from everyone else's authenticator (@frankhsu)
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support okta.com and okta enterprise installations
OKTA_HOST = os.environ.get('OKTA_HOST') or 'okta.com'

class OktaMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/oauth2/v1/authorize" % OKTA_HOST
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/login/oauth2/v1/token" % OKTA_HOST


class OktaLoginHandler(OAuthLoginHandler, OktaMixin):
    pass


class OktaOAuthenticator(OAuthenticator):

    login_service = "Okta"

    # deprecated names
    okta_client_id = Unicode(config=True, help="DEPRECATED")
    def _okta_client_id_changed(self, name, old, new):
        self.log.warn("okta_client_id is deprecated, use client_id")
        self.client_id = new
    okta_client_secret = Unicode(config=True, help="DEPRECATED")
    def _okta_client_secret_changed(self, name, old, new):
        self.log.warn("okta_client_secret is deprecated, use client_secret")
        self.client_secret = new

    client_id_env = 'OKTA_CLIENT_ID'
    client_secret_env = 'OKTA_CLIENT_SECRET'
    login_handler = OktaLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a Okta Access Token
        #
        # See: http://developer.okta.com/docs/api/resources/oidc.html#token-request

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="authorization_code",
            code=code,
            redirect_uri=self.get_callback_url(handler),
        )

        url = url_concat("https://%s/login/oauth/v1/token" % OKTA_HOST,
                         params)

        self.log.info(url)
        usrPass = self.client_id + ":" + self.client_secret
        client_creds = base64.b64encode(usrPass)
        bb_header = {"Content-Type":
                     "application/x-www-form-urlencoded;charset=utf-8",
                     "Authorization": "Basic {}".format(client_creds)}
        req = HTTPRequest(url,
                          method="POST",
                          body=urllib.parse.urlencode(params).encode('utf-8'),
                          headers=bb_header
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("https://%s/oauth2/v1/userinfo" % OKTA_HOST,
                          method="POST",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["email"]


class LocalOktaOAuthenticator(LocalAuthenticator, OktaOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
