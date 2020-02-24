"""
Custom Authenticator to use OpenShift OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from traitlets import Bool, Unicode, default

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthenticator


class OpenShiftOAuthenticator(OAuthenticator):

    login_service = "OpenShift"

    scope = ['user:info']

    openshift_url = Unicode(
        os.environ.get('OPENSHIFT_URL') or 'https://localhost:8443', config=True
    )

    openshift_auth_api_url = Unicode(config=True)

    validate_cert = Bool(
        True, config=True, help="Set to False to disable certificate validation"
    )

    @default("openshift_auth_api_url")
    def _openshift_auth_api_url_default(self):
        return self.openshift_url

    openshift_rest_api_url = Unicode(config=True)

    @default("openshift_rest_api_url")
    def _openshift_rest_api_url_default(self):
        return self.openshift_url

    @default("authorize_url")
    def _authorize_url_default(self):
        return "%s/oauth/authorize" % self.openshift_auth_api_url

    @default("token_url")
    def _token_url_default(self):
        return "%s/oauth/token" % self.openshift_auth_api_url

    @default("userdata_url")
    def _userdata_url_default(self):
        return "%s/apis/user.openshift.io/v1/users/~" % self.openshift_rest_api_url

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a OpenShift Access Token
        #
        # See: https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html#api-authentication

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="authorization_code",
            code=code,
        )

        url = url_concat(self.token_url, params)

        req = HTTPRequest(
            url,
            method="POST",
            validate_cert=self.validate_cert,
            headers={"Accept": "application/json"},
            body='',  # Body is required for a POST...
        )

        resp = await http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token),
        }

        req = HTTPRequest(
            self.userdata_url,
            method="GET",
            validate_cert=self.validate_cert,
            headers=headers,
        )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return {
            'name': resp_json['metadata']['name'],
            'auth_state': {'access_token': access_token, 'openshift_user': resp_json},
        }


class LocalOpenShiftOAuthenticator(LocalAuthenticator, OpenShiftOAuthenticator):

    """A version that mixes in local system user creation"""

    pass
