"""
A JupyterHub authenticator class for use with Bitbucket as an identity provider.
"""

import os

from jupyterhub.auth import LocalAuthenticator
from tornado.httputil import url_concat
from traitlets import Set, default

from .oauth2 import OAuthenticator


class BitbucketOAuthenticator(OAuthenticator):
    client_id_env = "BITBUCKET_CLIENT_ID"
    client_secret_env = "BITBUCKET_CLIENT_SECRET"
    user_auth_state_key = "bitbucket_user"

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "Bitbucket")

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://bitbucket.org/site/oauth2/authorize"

    @default("token_url")
    def _token_url_default(self):
        return "https://bitbucket.org/site/oauth2/access_token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return "https://api.bitbucket.org/2.0/user"

    allowed_teams = Set(
        config=True,
        help="""
        Allow members of selected Bitbucket teams to sign in.
        """,
    )

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "team_whitelist": ("allowed_teams", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    team_whitelist = Set(
        config=True,
        help="""
        .. deprecated:: 0.12

           Use :attr:`allowed_teams`.
        """,
    )

    async def _fetch_user_teams(self, access_token, token_type):
        """
        Get user's team memberships via bitbucket's API.
        """
        headers = self.build_userdata_request_headers(access_token, token_type)
        next_page = url_concat(
            "https://api.bitbucket.org/2.0/workspaces", {'role': 'member'}
        )

        user_teams = set()
        while next_page:
            resp_json = await self.httpfetch(next_page, method="GET", headers=headers)
            next_page = resp_json.get('next', None)
            user_teams |= {entry["name"] for entry in resp_json["values"]}
        return user_teams

    async def update_auth_model(self, auth_model):
        """
        Fetch and store `user_teams` in auth state if `allowed_teams` is
        configured.
        """
        user_teams = set()
        if self.allowed_teams:
            access_token = auth_model["auth_state"]["token_response"]["access_token"]
            token_type = auth_model["auth_state"]["token_response"]["token_type"]
            user_teams = await self._fetch_user_teams(access_token, token_type)
        # sets are not JSONable, cast to list for auth_state
        auth_model["auth_state"]["user_teams"] = list(user_teams)

        return auth_model

    async def check_allowed(self, username, auth_model):
        """
        Overrides the OAuthenticator.check_allowed to also allow users part of
        `allowed_teams`.
        """
        if await super().check_allowed(username, auth_model):
            return True

        if self.allowed_teams:
            user_teams = set(auth_model["auth_state"].get("user_teams", []))
            if user_teams & self.allowed_teams:
                return True

        # users should be explicitly allowed via config, otherwise they aren't
        return False


class LocalBitbucketOAuthenticator(LocalAuthenticator, BitbucketOAuthenticator):
    """A version that mixes in local system user creation"""
