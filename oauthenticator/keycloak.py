"""
Custom Authenticator to use Keycloak OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""

import json
import os
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.handlers import LogoutHandler
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthenticator

class KeycloakMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = os.getenv('KEYCLOAK_AUTH_URL',
                                     "https://localhost:8080/auth/realms/master/protocol/openid-connect/auth")
    _OAUTH_ACCESS_TOKEN_URL = os.getenv('KEYCLOAK_TOKEN_URL',
                                        "https://localhost:8080/auth/realms/master/protocol/openid-connect/token")
    _OAUTH_LOGOUT_URL = os.getenv('KEYCLOAK_LOGOUT_URL',
                                     "https://localhost:8080/auth/realms/master/protocol/openid-connect/logout")
    _OAUTH_USERINFO_URL = os.getenv('KEYCLOAK_USERINFO_URL',
                                  "https://localhost:8080/auth/realms/master/protocol/openid-connect/userinfo")


class KeycloakLoginHandler(OAuthLoginHandler, KeycloakMixin):
    pass


class KeycloakLogoutHandler(LogoutHandler, KeycloakMixin):
    def get(self):
        params = dict(
            redirect_uri="%s://%s%slogout" % (
                self.request.protocol, self.request.host,
                self.hub.server.base_url)
        )

        logout_url = KeycloakMixin._OAUTH_LOGOUT_URL
        logout_url = url_concat(logout_url, params)
        self.redirect(logout_url, permanent=False)


class KeycloakOAuthenticator(OAuthenticator, KeycloakMixin):
    login_service = "Keycloak"
    login_handler = KeycloakLoginHandler

    def logout_url(self, base_url):
        return url_path_join(base_url, 'oauth_logout')

    def get_handlers(self, app):
        handlers = OAuthenticator.get_handlers(self, app)
        handlers.extend([(r'/oauth_logout', KeycloakLogoutHandler)])
        return handlers

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")

        http_client = AsyncHTTPClient()

        params = dict(
            grant_type='authorization_code',
            code=code,
            redirect_uri=self.get_callback_url(handler),
        )

        tokenUrl = KeycloakMixin._OAUTH_ACCESS_TOKEN_URL

        tokenReq = HTTPRequest(tokenUrl,
                               method="POST",
                               headers={"Accept": "application/json",
                                        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
                               auth_username=self.client_id,
                               auth_password=self.client_secret,
                               body=urllib.parse.urlencode(params).encode(
                                   'utf-8'),
                               )

        tokenResp = yield http_client.fetch(tokenReq)
        tokenResp_json = json.loads(tokenResp.body.decode('utf8', 'replace'))
        access_token = tokenResp_json['access_token']
        if not access_token:
            raise web.HTTPError(400, "failed to get access token")

        self.log.info('oauth token: %r', access_token)
        userInfoUrl = KeycloakMixin._OAUTH_USERINFO_URL
        userInfoReq = HTTPRequest(userInfoUrl,
                                  method="GET",
                                  headers={"Accept": "application/json",
                                           "Authorization": "Bearer %s" % access_token},
                                  )
        userInfoResp = yield http_client.fetch(userInfoReq)
        userInfoResp_json = json.loads(
            userInfoResp.body.decode('utf8', 'replace'))

        return userInfoResp_json['preferred_username']


class LocalKeycloakOAuthenticator(LocalAuthenticator, KeycloakOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
