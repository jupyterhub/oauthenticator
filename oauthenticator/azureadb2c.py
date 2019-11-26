"""
Custom Authenticator to use Azure AD B2C with JupyterHub

"""

import json
import jwt
import os
import urllib
import hashlib
from urllib.parse import quote

from tornado.auth import OAuth2Mixin
from tornado.log import app_log
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, default

from oauth2 import OAuthLoginHandler, OAuthenticator


def azure_token_url():
    return os.environ.get('OAUTH_ACCESS_TOKEN_URL', '') 


def azure_authorize_url():
    return os.environ.get('OAUTH_AUTHORIZE_URL', '') + '&scope=' + quote(os.environ.get('OAUTH_SCOPE', ''))


class AzureAdB2CMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = azure_token_url() 
    _OAUTH_AUTHORIZE_URL = azure_authorize_url()
    

class AzureAdB2CLoginHandler(OAuthLoginHandler, AzureAdB2CMixin):
    pass


class AzureAdB2COAuthenticator(OAuthenticator):
    login_service = Unicode(
               os.environ.get('AAD_LOGIN_SERVICE_NAME', 'Azure AD B2C'),
                config=True,
                help="Tenant")

    login_handler = AzureAdB2CLoginHandler

    username_claim = Unicode(
               os.environ.get('AAD_USERNAME_CLAIM', 'upn'),
                config=True,
                help="Tenant")

    @default('username_claim')
    def _username_claim_default(self):
        return 'upn'


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

        url = azure_token_url() 

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

        app_log.info("Response %s", resp_json)
        access_token = resp_json['access_token']

        id_token = resp_json['id_token']
        decoded = jwt.decode(id_token, verify=False)

        #userdict = {"name": self.get_normalizedUserIdFromUPN(decoded[self.username_claim])}
        userdict = {"name": decoded[self.username_claim]}


        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        return userdict


class LocalAzureAdB2COAuthenticator(LocalAuthenticator, AzureAdB2COAuthenticator):
    """A version that mixes in local system user creation"""
    pass
