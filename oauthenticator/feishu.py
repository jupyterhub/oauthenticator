"""
Custom Authenticator to use FeiShu OAuth with JupyterHub
Developed by Yuandong Yang and Qiang Ju from Tezign.com
"""
import os
from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from traitlets import Bool, List, Unicode, default

from .oauth2 import OAuthenticator
import json


class FeiShuOAuthenticator(OAuthenticator):

    login_service = 'FeiShu'

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request",
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

    @default("http_client")
    def _default_http_client(self):
        return AsyncHTTPClient(force_instance=True, defaults=dict(validate_cert=self.tls_verify))

    def _get_app_access_token(self):
        req = HTTPRequest(
            'https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/',
            method="POST",
            headers={
                'Content-Type': "application/json; charset=utf-8",
            },
            body=json.dumps({
                'app_id': self.client_id,
                'app_secret': self.client_secret
            }),
        )
        return self.fetch(req, "fetching app access token")

    def _get_user_access_token(self, app_access_token, code):
        req = HTTPRequest(
            'https://open.feishu.cn/open-apis/authen/v1/access_token',
            method="POST",
            headers={
                'Content-Type': "application/json; charset=utf-8",
                'Authorization': f'Bearer {app_access_token}'
            },
            body=json.dumps({
                "grant_type": "authorization_code",
                "code": code
            }),
        )
        return self.fetch(req, "fetching user access token")

    def _get_user_info(self, user_access_token, union_id):
        req = HTTPRequest(
            f'https://open.feishu.cn/open-apis/contact/v3/users/{union_id}?user_id_type=union_id',
            method="GET",
            headers={
                'Content-Type': "application/json; charset=utf-8",
                'Authorization': f'Bearer {user_access_token}'
            }
        )
        return self.fetch(req, "fetching user info")

    @staticmethod
    def _create_auth_state(token_response, user_info):
        access_token = token_response['access_token']
        refresh_token = token_response.get('refresh_token', None)
        scope = token_response.get('scope', '')
        if isinstance(scope, str):
            scope = scope.split(' ')

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'oauth_user': user_info,
            'scope': scope,
        }

    @staticmethod
    def check_user_in_groups(member_groups, allowed_groups):
        return bool(set(member_groups) & set(allowed_groups))

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        app_access_token_resp = await self._get_app_access_token()
        user_access_token_resp = await self._get_user_access_token(app_access_token_resp['app_access_token'], code)
        user_info_resp = await self._get_user_info(user_access_token_resp['data']['access_token'], user_access_token_resp['data']['union_id'])
        user_info = user_info_resp['data']['user']

        user_info = {
            'name': user_info['name'],
            'auth_state': self._create_auth_state(user_access_token_resp['data'], user_info)
        }

        if self.allowed_groups:
            self.log.info('Validating if user claim groups match any of {}'.format(self.allowed_groups))
            groups = user_info['department_ids']
            if self.check_user_in_groups(groups, self.allowed_groups):
                user_info['admin'] = self.check_user_in_groups(groups, self.admin_groups)
            else:
                user_info = None

        return user_info


class LocalFeiShuOAuthenticator(LocalAuthenticator, FeiShuOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
