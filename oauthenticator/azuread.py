"""
Custom Authenticator to use Azure AD with JupyterHub

"""

import json
import jwt
import os
import re
import string
import urllib
import sys

from tornado.auth import OAuth2Mixin
from tornado.log import app_log
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import List, Set, Unicode

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator


def azure_token_url_for(tentant):
    return 'https://login.microsoftonline.com/{0}/oauth2/token'.format(tentant)


def azure_authorize_url_for(tentant):
    return 'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(
        tentant)


class AzureAdMixin(OAuth2Mixin):
    tenant_id = os.environ.get('AAD_TENANT_ID', '')
    _OAUTH_ACCESS_TOKEN_URL = azure_token_url_for(tenant_id)
    _OAUTH_AUTHORIZE_URL = azure_authorize_url_for(tenant_id)


class AzureAdLoginHandler(OAuthLoginHandler, AzureAdMixin):
    pass


class AzureAdOAuthenticator(OAuthenticator):
    login_service = "Azure AD"

    login_handler = AzureAdLoginHandler

    tenant_id = Unicode(config=True)

    def get_tenant(self):
        if hasattr(self, 'tenant_id') and self.tenant_id:
            app_log.info('ID3: {0}'.format(self.tenant_id))
            return self.tenant_id
        else:
            tenant_id = Unicode(
                os.environ.get('AAD_TENANT_ID', ''),
                config=True,
                help="Tenant")
            app_log.info('ID4: {0}'.format(tenant_id))
            return tenant_id

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        http_client = AsyncHTTPClient()

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type='authorization_code',
            code=code,
            resource=self.client_id,
            redirect_uri=self.get_callback_url(handler))

        data = urllib.parse.urlencode(
            params, doseq=True, encoding='utf-8', safe='=')

        url = azure_token_url_for(self.get_tenant())

        headers = {
            'Content-Type':
            'application/x-www-form-urlencoded; ; charset=UTF-8"'
        }
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=data  # Body is required for a POST...
        )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        # app_log.info("Response %s", resp_json)
        access_token = resp_json['access_token']

        id_token = resp_json['id_token']
        decoded = jwt.decode(id_token, verify=False)

        userdict = {"name": decoded['name']}
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        return userdict


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
