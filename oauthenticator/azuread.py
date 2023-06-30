"""
A JupyterHub authenticator class for use with Azure AD as an identity provider.
"""
import os

import jwt
from jupyterhub.auth import LocalAuthenticator
from traitlets import Unicode, default

from .oauth2 import OAuthenticator


class AzureAdOAuthenticator(OAuthenticator):
    user_auth_state_key = "user"

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "Azure AD")

    @default("username_claim")
    def _username_claim_default(self):
        return "name"

    tenant_id = Unicode(
        config=True,
        help="""
        An Azure tenant ID for which an OAuth application is registered via
        `client_id` and `client_secret`.

        This is used to set the default values of `authorize_url` and
        `token_url`.
        """,
    )

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/token"

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
