"""
Custom Authenticator to use Azure AD with JupyterHub
"""

import json
import os
import urllib
from distutils.version import LooseVersion as V

import jwt
from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.log import app_log

from traitlets import Unicode, default
from traitlets.traitlets import Bool

from .oauth2 import OAuthenticator

# pyjwt 2.0 has changed its signature,
# but mwoauth pins to pyjwt 1.x
PYJWT_2 = V(jwt.__version__) >= V("2.0")


class AzureAdOAuthenticator(OAuthenticator):
    login_service = Unicode(
		os.environ.get('LOGIN_SERVICE', 'Azure AD'),
		config=True,
		help="""Azure AD domain name string, e.g. My College"""
	)

    tenant_id = Unicode(config=True, help="The Azure Active Directory Tenant ID")

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')

    username_claim = Unicode(config=True, help="User's attribute to return as username")

    @default('username_claim')
    def _username_claim_default(self):
        return 'name'

    username_claim_request = Bool(config=True, help="Allow an additional user attribute request if username_claim is not in the initial response")

    @default('username_claim_request')
    def _username_claim_request_default(self):
        return False

    @default("authorize_url")
    def _authorize_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(self.tenant_id)

    @default("token_url")
    def _token_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/token'.format(self.tenant_id)

    graph_url = Unicode(config=True, help="URL of the Microsoft Graph Endpoint")

    @default('graph_url')
    def _graph_url_default(self):
        return 'https://graph.microsoft.com/v1.0'

    async def get_user_attribute(self, oid, attr):

        http_client = AsyncHTTPClient()

        params = dict(
            scope=["https://graph.microsoft.com/.default"],
            client_secret=self.client_secret,
            grant_type="client_credentials",
            client_id=self.client_id,
        )

        data = urllib.parse.urlencode(
            params, doseq=True, encoding='utf-8', safe='=')

        url = self.token_url

        headers = {
            'Content-Type':
            'application/x-www-form-urlencoded; charset=UTF-8'
        }
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=data  # Body is required for a POST...
        )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json["access_token"]

        url = '{0}/users/{1}?$select={2}'.format(self.graph_url, oid, attr)

        headers = {
            'Authorization':
            'Bearer {0}'.format(access_token)
        }
        req = HTTPRequest(
            url,
            method="GET",
            headers=headers,
        )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        # app_log.debug("[GetUserAttribute] Response %s", resp_json)

        return resp_json[attr]

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type='authorization_code',
            code=code,
            redirect_uri=self.get_callback_url(handler))

        data = urllib.parse.urlencode(
            params, doseq=True, encoding='utf-8', safe='=')

        url = self.token_url

        headers = {
            'Content-Type':
            'application/x-www-form-urlencoded; charset=UTF-8'
        }
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=data  # Body is required for a POST...
        )

        resp_json = await self.fetch(req)

        access_token = resp_json['access_token']
        id_token = resp_json['id_token']

        if PYJWT_2:
            decoded = jwt.decode(
                id_token,
                options={"verify_signature": False},
                audience=self.client_id,
            )
        else:
            # pyjwt 1.x
            decoded = jwt.decode(id_token, verify=False)

        # try to set the name using the username_claim attribute
        # if this fails, try to get it from a specific Microsoft Graph Query (if enabled)
        try:
            userdict = {"name": decoded[self.username_claim]}
        except KeyError as e:
            if self.username_claim_request:
                app_log.debug("Trying to get username_claim attribute '{0}' for user '{1}'".format(self.username_claim, decoded['oid']))
                userdict = {"name": await self.get_user_attribute(decoded['oid'], self.username_claim)}
            else:
                app_log.debug("Failed to get username_claim '{0}' for user '{1}' and additional request is not enabled".format(self.username_claim, decoded['oid']))
                raise KeyError("Failed to get username_claim '{0}' for user '{1}'".format(self.username_claim, decoded['oid']))

        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        return userdict


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
