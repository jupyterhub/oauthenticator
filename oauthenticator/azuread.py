"""
Custom Authenticator to use Azure AD with JupyterHub
"""
import os

import jwt
from jupyterhub.auth import LocalAuthenticator
from traitlets import Unicode, default

from .oauth2 import OAuthenticator


class AzureAdOAuthenticator(OAuthenticator):
    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Azure AD'),
        config=True,
        help="""Azure AD domain name string, e.g. My College""",
    )

    tenant_id = Unicode(config=True, help="The Azure Active Directory Tenant ID")

    user_auth_state_key = "user"

    user_groups_claim = Unicode(
        "", config=True, help="Name of claim containing user group memberships"
    )

    @default("username_claim")
    def _username_claim_default(self):
        return "name"

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/token"

    async def update_auth_model(self, auth_model, **kwargs):
        auth_model = await super().update_auth_model(auth_model, **kwargs)

        user_info = auth_model["auth_state"][self.user_auth_state_key]
        auth_model["groups"] = user_info.get(self.user_groups_claim)

        return auth_model

    async def token_to_user(self, token_info):
        id_token = token_info['id_token']
        decoded = jwt.decode(
            id_token,
            options={"verify_signature": False},
            audience=self.client_id,
        )

        return decoded


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""
