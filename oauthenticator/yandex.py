"""
Custom Authenticator to use Yandex.Passport OAuth with JupyterHub

Created by Dmitry Gerasimenko (@kidig)
"""


import json
import os
import urllib.parse

from jupyterhub.auth import LocalAuthenticator
from tornado import gen
from tornado.auth import OAuth2Mixin
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError
from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

YANDEX_OAUTH_HOST = os.environ.get('YANDEX_OAUTH_HOST', 'https://oauth.yandex.ru')
YANDEX_LOGIN_HOST = os.environ.get('YANDEX_LOGIN_HOST', 'https://login.yandex.ru')


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "OAuth {}".format(access_token),
    }


class YandexPassportMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "%s/authorize" % YANDEX_OAUTH_HOST
    _OAUTH_ACCESS_TOKEN_URL = "%s/token" % YANDEX_OAUTH_HOST


class YandexPassportLoginHandler(OAuthLoginHandler, YandexPassportMixin):
    pass


class YandexPassportOAuthenticator(OAuthenticator):
    client_id_env = "YANDEX_PASSPORT_CLIENT_ID"
    client_secret_env = "YANDEX_PASSPORT_CLIENT_SECRET"
    login_handler = YandexPassportLoginHandler

    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Yandex.Passport'),
        config=True,
        help="""Yandex Service string, e.g. Yandex"""
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)

        if not code:
            raise HTTPError(400, "oauth_callback made without a token")

        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a YandexPassport Access Token
        #
        post_params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            grant_type='authorization_code',
        )

        req = HTTPRequest(
            "%s/token" % YANDEX_OAUTH_HOST,
            method="POST",
            headers={
                "Accept": "application/json",

            },
            body=urllib.parse.urlencode(post_params).encode('utf-8'),
        )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        req = HTTPRequest("%s/info" % YANDEX_LOGIN_HOST,
                          method="GET",
                          headers=_api_headers(access_token))

        resp = yield http_client.fetch(req)
        user_info = json.loads(resp.body.decode('utf8', 'replace'))

        username = user_info['login']

        if not username:
            return None

        return {
            'name': username,
            'auth_state': {
                'access_token': access_token,
                'yandex_user': user_info
            }
        }


class LocalYandexPassportOAuthenticator(LocalAuthenticator, YandexPassportOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
