"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""


import json
import os
import base64
import urllib

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict, Bool, Union, default, observe
from .traitlets import Callable

from .oauth2 import OAuthLoginHandler, OAuthenticator


class GenericOAuthenticator(OAuthenticator):

    login_service = Unicode("OAuth 2.0", config=True)

    extra_params = Dict(help="Extra parameters for first POST request").tag(config=True)

    username_key = Union(
        [Unicode(os.environ.get('OAUTH2_USERNAME_KEY', 'username')), Callable()],
        config=True,
        help="""
        Userdata username key from returned json for USERDATA_URL.

        Can be a string key name or a callable that accepts the returned
        json (as a dict) and returns the username.  The callable is useful
        e.g. for extracting the username from a nested object in the
        response.
        """,
    )

    userdata_params = Dict(
        help="Userdata params to get user data login information"
    ).tag(config=True)

    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information",
    )
    userdata_token_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_REQUEST_TYPE', 'header'),
        config=True,
        help="Method for sending access token in userdata request. Supported methods: header, url. Default: header",
    )

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request",
    )

    basic_auth = Bool(
        os.environ.get('OAUTH2_BASIC_AUTH', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable basic authentication for access token request",
    )

    def http_client(self):
        return AsyncHTTPClient(force_instance=True, defaults=dict(validate_cert=self.tls_verify))

    def _get_headers(self):
        headers = {"Accept": "application/json", "User-Agent": "JupyterHub"}

        if self.basic_auth:
            b64key = base64.b64encode(
                bytes("{}:{}".format(self.client_id, self.client_secret), "utf8")
            )
            headers.update({"Authorization": "Basic {}".format(b64key.decode("utf8"))})
        return headers

    async def _get_token(self, http_client, headers, params):
        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the $OAUTH2_TOKEN_URL environment variable")

        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=urllib.parse.urlencode(params),
        )

        resp = await http_client.fetch(req)
        return json.loads(resp.body.decode('utf8', 'replace'))

    async def _get_user_data(self, http_client, token_response):
        access_token = token_response['access_token']
        token_type = token_response['token_type']

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token),
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        if self.userdata_token_method == "url":
            url = url_concat(self.userdata_url, dict(access_token=access_token))

        req = HTTPRequest(
            url,
            method=self.userdata_method,
            headers=headers,
        )
        resp = await http_client.fetch(req)
        
        return json.loads(resp.body.decode('utf8', 'replace'))

    def _create_auth_state(self, token_response, user_data_response):
        access_token = token_response['access_token']
        refresh_token = token_response.get('refresh_token', None)
        scope = token_response.get('scope', '')
        if isinstance(scope, str):
            scope = scope.split(' ')

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'oauth_user': user_data_response,
            'scope': scope,
        }

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = self.http_client()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
        )
        params.update(self.extra_params)

        headers = self._get_headers()

        token_resp_json = await self._get_token(http_client, headers, params)

        user_data_resp_json = await self._get_user_data(http_client, token_resp_json)

        if callable(self.username_key):
            name = self.username_key(user_data_resp_json)
        else:
            name = user_data_resp_json.get(self.username_key)
            if not name:
                self.log.error(
                    "OAuth user contains no key %s: %s", self.username_key, user_data_resp_json
                )
                return

        return {
            'name': name,
            'auth_state': self._create_auth_state(token_resp_json, user_data_resp_json)
        }


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):

    """A version that mixes in local system user creation"""

    pass
