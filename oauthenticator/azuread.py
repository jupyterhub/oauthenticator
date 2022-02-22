"""
Custom Authenticator to use Azure AD with JupyterHub
"""
import os
import urllib
from distutils.version import LooseVersion as V

import jwt
from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPRequest
from traitlets import default
from traitlets import Unicode

from .oauth2 import OAuthenticator


# pyjwt 2.0 has changed its signature,
# but mwoauth pins to pyjwt 1.x
PYJWT_2 = V(jwt.__version__) >= V("2.0")


class AzureAdOAuthenticator(OAuthenticator):
    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Azure AD'),
        config=True,
        help="""Azure AD domain name string, e.g. My College""",
    )

    tenant_id = Unicode(config=True, help="The Azure Active Directory Tenant ID")

    admin_role_id = Unicode(config=True, help="The GUID of the Azure Active Directory Group containing admin users")

    allowed_user_role_id = Unicode(config=True, help="The GUID of the Azure Active Direcetory Group containing allowed users")

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')

    username_claim = Unicode(config=True)

    @default('username_claim')
    def _username_claim_default(self):
        return 'name'

    @default("authorize_url")
    def _authorize_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(
            self.tenant_id
        )

    @default("token_url")
    def _token_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/token'.format(
            self.tenant_id
        )

    @default('scope')
    def _scope_default(self):
        return ['openid']

    role_claim = Unicode(config=True)

    @default("role_claim")
    def _role_claim_default(self):
        return 'roles'

    def _claim_has_role(self, token, role_id):
        roles = [] if self.role_claim not in token.keys() else token[self.role_claim]
        return role_id in roles

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type='authorization_code',
            code=code,
            redirect_uri=self.get_callback_url(handler),
        )

        data = urllib.parse.urlencode(params, doseq=True, encoding='utf-8', safe='=')

        url = self.token_url

        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=data,  # Body is required for a POST...
        )

        resp_json = await self.fetch(req)

        self.log.debug("Azure AD Token Response: %s", resp_json)

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

        has_admin_role = self._claim_has_role(decoded, self.admin_role_id)
        has_allowed_role = self._claim_has_role(decoded, self.allowed_user_role_id) or has_admin_role
        allowed = has_allowed_role if self.allowed_user_role_id else True

        userdict = {"name": decoded[self.username_claim]}

        if allowed:
            self.log.debug("Access to Azure AD User %s is permitted (has_admin_role: %r, has_allowed_role: %r)", userdict["name"], has_admin_role, has_allowed_role)
        if has_admin_role:
            userdict["admin"] = has_admin_role
            self.log.debug("Azure AD User %s has been granted admin privileges", userdict["name"])
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        return userdict if allowed else None

class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
