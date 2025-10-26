"""
A JupyterHub authenticator class for use with Azure AD as an identity provider.
"""

import os

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

    user_groups_claim = Unicode(
        "",
        config=True,
        help="""
        .. deprecated:: 17.0

            Use :attr:`auth_state_groups_key` instead.
        """,
    )

    @default('auth_state_groups_key')
    def _auth_state_groups_key_default(self):
        key = "user.groups"
        if self.user_groups_claim:
            key = f"{self.user_auth_state_key}.{self.user_groups_claim}"
            cls = self.__class__.__name__
            self.log.warning(
                f"{cls}.user_groups_claim is deprecated in OAuthenticator 17. Use {cls}.auth_state_groups_key = {key!r}"
            )
        return key

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

    @default("userdata_from_id_token")
    def _userdata_from_id_token_default(self):
        return True


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""
