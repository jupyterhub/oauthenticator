"""
Authenticator to use ORCID iD OAuth with JupyterHub

Derived from the GitHub OAuth authenticator.
"""
import os

from jupyterhub.auth import LocalAuthenticator
from traitlets import Unicode, default

from .oauth2 import OAuthenticator


# TODO: Implementations for `user_is_authorized` and `update_auth_model` for auth logic
class OrcidOAuthenticator(OAuthenticator):
    _deprecated_oauth_aliases = {
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "ORCID iD"
    user_auth_state_key = "orcid_user"

    @default("scope")
    def _scope_default(self):
        return ["openid", "/authenticate"]

    def normalize_username(self, username):
        """
        Override normalize_username to avoid lowercasing (ORCID iDs with trailing valid 'X')
        """
        return username

    @default("username_claim")
    def _username_claim_default(self):
        return "sub"

    orcid_url = Unicode("https://orcid.org", config=True)

    @default("orcid_url")
    def _orcid_url_default(self):
        orcid_url = os.environ.get("ORCID_URL")
        if not orcid_url:
            orcid_url = "https://orcid.org"
        return orcid_url

    orcid_api = Unicode("https://pub.orcid.org", config=True)

    @default("orcid_api")
    def _orcid_api_default(self):
        orcid_api = os.environ.get("ORCID_API")
        if not orcid_api:
            orcid_api = "https://pub.orcid.org"
        return orcid_api

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"{self.orcid_url}/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"{self.orcid_url}/oauth/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"{self.orcid_url}/oauth/userinfo"

    client_id_env = 'ORCID_CLIENT_ID'
    client_secret_env = 'ORCID_CLIENT_SECRET'


class LocalOrcidOAuthenticator(LocalAuthenticator, OrcidOAuthenticator):

    """A version that mixes in local system user creation"""
