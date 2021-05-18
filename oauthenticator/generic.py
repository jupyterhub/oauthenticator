"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""
import base64
import os
from urllib.parse import urlencode

from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import AsyncHTTPClient
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import Bool
from traitlets import default
from traitlets import Dict
from traitlets import List
from traitlets import Unicode
from traitlets import Union

from .oauth2 import OAuthenticator
from .traitlets import Callable


class GenericOAuthenticator(OAuthenticator):
    login_service = Unicode("OAuth 2.0", config=True)

    extra_params = Dict(help="Extra parameters for first POST request").tag(config=True)

    claim_groups_key = Union(
        [Unicode(os.environ.get('OAUTH2_GROUPS_KEY', 'groups')), Callable()],
        config=True,
        help="""
        Userdata groups claim key from returned json for USERDATA_URL.

        Can be a string key name or a callable that accepts the returned
        json (as a dict) and returns the groups list. The callable is useful
        e.g. for extracting the groups from a nested object in the response.
        """,
    )

    allowed_groups = List(
        Unicode(),
        config=True,
        help="Automatically allow members of selected groups",
    )

    admin_groups = List(
        Unicode(),
        config=True,
        help="Groups whose members should have Jupyterhub admin privileges",
    )

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

    @default("http_client")
    def _default_http_client(self):
        return AsyncHTTPClient(
            force_instance=True, defaults=dict(validate_cert=self.tls_verify)
        )

    def _get_headers(self):
        headers = {"Accept": "application/json", "User-Agent": "JupyterHub"}

        if self.basic_auth:
            b64key = base64.b64encode(
                bytes("{}:{}".format(self.client_id, self.client_secret), "utf8")
            )
            headers.update({"Authorization": "Basic {}".format(b64key.decode("utf8"))})
        return headers

    def _get_token(self, headers, params):
        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the $OAUTH2_TOKEN_URL environment variable")

        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=urlencode(params),
        )
        return self.fetch(req, "fetching access token")

    def _get_user_data(self, token_response):
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

        req = HTTPRequest(url, headers=headers)
        return self.fetch(req, "fetching user data")

    @staticmethod
    def _create_auth_state(token_response, user_data_response):
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

    @staticmethod
    def check_user_in_groups(member_groups, allowed_groups):
        return bool(set(member_groups) & set(allowed_groups))

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
        )
        params.update(self.extra_params)

        headers = self._get_headers()

        token_resp_json = await self._get_token(headers, params)

        user_data_resp_json = await self._get_user_data(token_resp_json)

        if callable(self.username_key):
            name = self.username_key(user_data_resp_json)
        else:
            name = user_data_resp_json.get(self.username_key)
            if not name:
                self.log.error(
                    "OAuth user contains no key %s: %s",
                    self.username_key,
                    user_data_resp_json,
                )
                return

        user_info = {
            'name': name,
            'auth_state': self._create_auth_state(token_resp_json, user_data_resp_json),
        }

        if self.allowed_groups:
            self.log.info(
                'Validating if user claim groups match any of {}'.format(
                    self.allowed_groups
                )
            )

            if callable(self.claim_groups_key):
                groups = self.claim_groups_key(user_data_resp_json)
            else:
                groups = user_data_resp_json.get(self.claim_groups_key)

            if not groups:
                self.log.error(
                    "No claim groups found for user! Something wrong with the `claim_groups_key` {}? {}".format(
                        self.claim_groups_key, user_data_resp_json
                    )
                )
                groups = []

            if self.check_user_in_groups(groups, self.allowed_groups):
                user_info['admin'] = self.check_user_in_groups(
                    groups, self.admin_groups
                )
            else:
                user_info = None

        return user_info


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
