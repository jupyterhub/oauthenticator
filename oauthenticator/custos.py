"""
Custos Authenticator to use  OAuth2 with JupyterHub
"""
import base64
import os
from urllib.parse import urlencode
import logging

import os
from jupyterhub.auth import LocalAuthenticator
from tornado import web
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import Bool
from traitlets import default
from traitlets import List
from traitlets import Unicode
from traitlets import validate

from .oauth2 import OAuthenticator
from .oauth2 import OAuthLoginHandler


class CustosLoginHandler(OAuthLoginHandler):
    """See //https://airavata.apache.org/custos/ for general information."""

    def authorize_redirect(self, *args, **kwargs):
        """Add idp, skin to redirect params"""
        extra_params = kwargs.setdefault('extra_params', {})
        extra_params["kc_idp_hint"] = 'oidc'
        return super().authorize_redirect(*args, **kwargs)


class CustosOAuthenticator(OAuthenticator):
    custos_host = Unicode(os.environ.get("CUSTOS_HOST") or "custos.scigap.org", config=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.login_service = "Custos Login"
        self.login_handler = CustosLoginHandler
        iam_host = ''
        if self.custos_host == 'custos.scigap.org':
            iam_host = "keycloak.custos.scigap.org:31000"
        elif self.custos_host == 'services.staging.usecustos.org':
            iam_host = "keycloak.staging.usecustos.org:30170"
        elif self.custos_host == 'service.usecustos.org':
            iam_host = "keycloak.usecustos.org:31161"
        x = super().client_id.split("-")
        tenant_id = x[len(x) - 1]
        self.iam_uri = "https://{}/auth/realms/{}/protocol/openid-connect/".format(iam_host, tenant_id)

    @default("authorize_url")
    def _authorize_url_default(self):
        return "{}auth".format(self.iam_uri)

    @default("token_url")
    def _token_url_default(self):
        return "https://{}/apiserver/identity-management/v1.0.0/token".format(self.custos_host)

    scope = List(
        Unicode(),
        default_value=['openid', 'email', 'org.cilogon.userinfo'],
        config=True,
        help="""The OAuth scopes to request.
        See cilogon_scope.md for details.
        At least 'openid' is required.
        """, )

    @validate('scope')
    def _validate_scope(self, proposal):
        """ensure openid is requested"""

        if 'openid' not in proposal.value:
            return ['openid'] + proposal.value
        return proposal.value

    async def authenticate(self, handler, data=None):
        """We set up auth_state based on additional Custos info if we
            receive it.
            """
        code = handler.get_argument("code")

        authS = "{}:{}".format(self.client_id, self.client_secret)
        tokenByte = authS.encode('utf-8')
        encodedBytes = base64.b64encode(tokenByte)
        auth_string = encodedBytes.decode('utf-8')
        headers = {"Accept": "application/json", "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(auth_string)}

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.oauth_callback_url,
            code=code,
            grant_type='authorization_code',
        )

        url = url_concat(self.token_url, params)

        req = HTTPRequest(url, headers=headers, method="POST", body='')

        token_response = await self.fetch(req)
        access_token = token_response['access_token']

        # Determine who the logged in user is
        params = dict(access_token=access_token)
        req = HTTPRequest(
            url_concat("https://{}/apiserver/identity-management/v1.0.0/user".format(self.custos_host), params),
            headers=headers,
        )
        resp_json = await self.fetch(req)

        userdict = {"name": resp_json['username']}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        # Save the token response and full Custos reply in auth state
        # These can be used for user provisioning
        #  in the Lab/Notebook environment.
        auth_state['token_response'] = token_response
        # store the whole user model in auth_state.custos_user
        # keep access_token as well, in case anyone was relying on it
        auth_state['access_token'] = access_token
        auth_state['custos_user'] = resp_json
        return userdict
