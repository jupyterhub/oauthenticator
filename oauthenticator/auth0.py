"""
A JupyterHub authenticator class for use with Auth0 as an identity provider.
"""
import os
from urllib.parse import urlencode

from jupyterhub.auth import LocalAuthenticator
from traitlets import Unicode, default

from .oauth2 import OAuthenticator


class Auth0OAuthenticator(OAuthenticator):
    user_auth_state_key = "auth0_user"

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "Auth0")

    @default("username_claim")
    def _username_claim_default(self):
        return "email"

    auth0_domain = Unicode(
        config=True,
        help="""
        The domain for your Auth0 account.

        Used to determine the default values for `logout_redirect_url`,
        `authorize_url`, `token_url`, and `userdata_url`.
        """,
    )

    @default("auth0_domain")
    def _auth0_domain_default(self):
        domain = os.getenv("AUTH0_DOMAIN", "")
        if domain:
            return domain
        if self.auth0_subdomain:
            return f"{self.auth0_subdomain}.auth0.com"
        raise ValueError(
            "Configuring either auth0_domain or auth0_subdomain is required"
        )

    logout_redirect_to_url = Unicode(
        config=True,
        help="""
        Redirect to this URL after the user is logged out.

        Must be explicitly added to the "Allowed Logout URLs" in the configuration
        for this Auth0 application. See https://auth0.com/docs/authenticate/login/logout/redirect-users-after-logout
        for more information.
        """,
    )

    auth0_subdomain = Unicode(
        config=True,
        help="""
        A shorthand for configuring `auth0_domain`, if configured to
        "something", it is the same as configuring `auth0_domain` to
        "something.auth0.com".
        """,
    )

    @default("auth0_subdomain")
    def _auth0_subdomain_default(self):
        # This is allowed to be empty unless auth0_domain is not supplied either
        return os.getenv("AUTH0_SUBDOMAIN", "")

    @default("logout_redirect_url")
    def _logout_redirect_url_default(self):
        url = f"https://{self.auth0_domain}/v2/logout"
        if self.logout_redirect_to_url:
            # If a redirectTo is set, we must also include the `client_id`
            # Auth0 expects `client_id` to be snake cased while `redirectTo` is camel cased
            params = urlencode(
                {"client_id": self.client_id, "redirectTo": self.logout_redirect_to_url}
            )
            url = f"{url}?{params}"
        return url

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"https://{self.auth0_domain}/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"https://{self.auth0_domain}/oauth/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"https://{self.auth0_domain}/userinfo"

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "username_key": ("username_claim", "16.0.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    username_key = Unicode(
        config=True,
        help="""
        .. deprecated:: 16.0

           Use :attr:`username_claim`.
        """,
    )


class LocalAuth0OAuthenticator(LocalAuthenticator, Auth0OAuthenticator):
    """A version that mixes in local system user creation"""
