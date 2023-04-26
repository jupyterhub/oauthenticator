"""
Custom Authenticator to use Bitbucket OAuth with JupyterHub
"""
from jupyterhub.auth import LocalAuthenticator
from tornado.httputil import url_concat
from traitlets import Set, default

from .oauth2 import OAuthenticator


class BitbucketOAuthenticator(OAuthenticator):
    _deprecated_oauth_aliases = {
        "team_whitelist": ("allowed_teams", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "Bitbucket"
    client_id_env = "BITBUCKET_CLIENT_ID"
    client_secret_env = "BITBUCKET_CLIENT_SECRET"
    user_auth_state_key = "bitbucket_user"

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://bitbucket.org/site/oauth2/authorize"

    @default("token_url")
    def _token_url_default(self):
        return "https://bitbucket.org/site/oauth2/access_token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return "https://api.bitbucket.org/2.0/user"

    team_whitelist = Set(
        help="Deprecated, use `BitbucketOAuthenticator.allowed_teams`",
        config=True,
    )

    allowed_teams = Set(
        config=True, help="Automatically allow members of selected teams"
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
        if self.allowed_teams:
            access_token = auth_model["auth_state"]["token_response"]["access_token"]
            token_type = auth_model["auth_state"]["token_response"]["token_type"]
            user_teams = await self._fetch_user_teams(access_token, token_type)
            auth_model["auth_state"]["user_teams"] = user_teams

        return auth_model

    async def check_allowed(self, username, auth_model):
        """
        Returns True for users allowed to be authorized.

        Overrides the OAuthenticator.check_allowed implementation to allow users
        either part of `allowed_users` or `allowed_teams`, and not just those
        part of `allowed_users`.
        """
        # allow admin users recognized via admin_users or update_auth_model
        if auth_model["admin"]:
            return True

        # if allowed_users or allowed_teams is configured, we deny users not
        # part of either
        if self.allowed_users or self.allowed_teams:
            user_teams = auth_model["auth_state"]["user_teams"]
            if username in self.allowed_users:
                return True
            if any(user_teams & self.allowed_teams):
                return True
            return False

        # otherwise, authorize all users
        return True


class LocalBitbucketOAuthenticator(LocalAuthenticator, BitbucketOAuthenticator):
    """A version that mixes in local system user creation"""
