"""
A JupyterHub authenticator class for use with Auth0 as an identity provider.
"""

import os

from jupyterhub.auth import LocalAuthenticator
from tornado.web import HTTPError
from traitlets import Bool, Unicode, default

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

    allow_unverified_email = Bool(
        False,
        config=True,
        help="""
        Allow login with unverified email.
        Not advisable, except for testing purposes.
        """,
    )

    @default("logout_redirect_url")
    def _logout_redirect_url_default(self):
        return f"https://{self.auth0_domain}/v2/logout"

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"https://{self.auth0_domain}/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"https://{self.auth0_domain}/oauth/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"https://{self.auth0_domain}/userinfo"

    async def check_allowed(self, username, auth_model):
        # A workaround for JupyterHub < 5.0 described in
        # https://github.com/jupyterhub/oauthenticator/issues/621
        if auth_model is None:
            return True

        # before considering allowing a username by being recognized in a list
        # of usernames or similar, we must ensure that the authenticated user
        # has a verified email and is part of hosted_domain if configured.
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_email = user_info["email"]

        if not user_info.get("email_verified"):
            if self.allow_unverified_email:
                message = (
                    f"Allowing login for {username} with unverified email {user_email}"
                )
                self.log.warning(message)
            else:
                message = f"Login with unverified email {user_email} is not allowed"
                self.log.warning(message)
                raise HTTPError(403, message)

        return await super().check_allowed(username, auth_model)

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
