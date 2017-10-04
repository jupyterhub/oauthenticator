"""
Custom Authenticator to use OpenShift OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator

OPENSHIFT_URL = os.environ.get('OPENSHIFT_URL') or 'https://localhost:8443'

class OpenShiftMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "%s/oauth/authorize" % OPENSHIFT_URL
    _OAUTH_ACCESS_TOKEN_URL = "%s/oauth/token" % OPENSHIFT_URL


class OpenShiftLoginHandler(OAuthLoginHandler, OpenShiftMixin):
    # This allows `Service Accounts as OAuth Clients` scenario
    # https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html#service-accounts-as-oauth-clients
    scope=['user:info']


class OpenShiftOAuthenticator(OAuthenticator):

    login_service = "OpenShift"

    login_handler = OpenShiftLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
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
            code=code
        )

        url = url_concat("%s/oauth/token" % OPENSHIFT_URL, params)

        req = HTTPRequest(url,
                          method="POST",
                          validate_cert=False,
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }

        req = HTTPRequest("%s/oapi/v1/users/~" % OPENSHIFT_URL,
                          method="GET",
                          validate_cert=False,
                          headers=headers)

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return {
            'name': resp_json['metadata']['name'],
            'auth_state': {
                'access_token': access_token,
                'openshift_user': resp_json,
            }
        }


class LocalOpenShiftOAuthenticator(LocalAuthenticator, OpenShiftOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
