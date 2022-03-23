"""
Custom Authenticator to use Azure AD with JupyterHub
"""
import os
import urllib

import jwt
from distutils.version import LooseVersion as V
from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPRequest
from traitlets import default
from traitlets import Set
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

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')

    username_claim = Unicode(config=True)

    @default('username_claim')
    def _username_claim_default(self):
        return 'name'

    app_roles_help_message = "More details on app roles: https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps"

    admin_users_app_roles = Set(
        config=True,
        help="Users with one of these app roles in their identity token claim 'roles' are treated as admins. "
        + app_roles_help_message,
    )

    allowed_users_app_roles = Set(
        config=True,
        help="Only users with one of these app roles in their identity token claim 'roles' will be allowed to login into JupyterHub. Admins do not fall under this restriction. "
        + app_roles_help_message,
    )

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

        userdict = {"name": decoded[self.username_claim]}
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        roles = set(auth_state['user'].get("roles", []))

        if self.admin_users_app_roles:
            if roles.intersection(self.admin_users_app_roles):
                userdict["admin"] = True
                return userdict

        if self.allowed_users_app_roles:
            if not roles.intersection(self.allowed_users_app_roles):
                return None

        return userdict


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
