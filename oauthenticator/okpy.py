"""
A JupyterHub authenticator class for use with Okpy as an identity provider.
"""
import os

from jupyterhub.auth import LocalAuthenticator
from tornado.auth import OAuth2Mixin
from traitlets import default

from .oauth2 import OAuthenticator


class OkpyOAuthenticator(OAuthenticator, OAuth2Mixin):
    user_auth_state_key = "okpy_user"

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "OK")

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://okpy.org/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return "https://okpy.org/oauth/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return "https://okpy.org/api/v3/user"

    @default("scope")
    def _default_scope(self):
        return ["email"]

    @default("username_claim")
    def _username_claim_default(self):
        return "email"

    @default("userdata_params")
    def _default_userdata_params(self):
        # Otherwise all responses from the API are wrapped in
        # an envelope that contains metadata about the response.
        # ref: https://okpy.github.io/documentation/ok-api.html
        return {"envelope": "false"}


class LocalOkpyOAuthenticator(LocalAuthenticator, OkpyOAuthenticator):
    """A version that mixes in local system user creation"""
