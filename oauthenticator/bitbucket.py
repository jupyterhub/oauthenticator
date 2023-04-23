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

    async def user_is_authorized(self, auth_model):
        access_token = auth_model["auth_state"]["token_response"]["access_token"]
        token_type = auth_model["auth_state"]["token_response"]["token_type"]

        username = auth_model["name"]
        if username in (self.allowed_users | self.admin_users):
            return True

        if self.allowed_teams:
            return await self._check_membership_allowed_teams(
                username, access_token, token_type
            )

        return False

    async def _check_membership_allowed_teams(self, username, access_token, token_type):
        """
        Verify team membership by calling bitbucket API.
        """
        headers = self.build_userdata_request_headers(access_token, token_type)
        next_page = url_concat(
            "https://api.bitbucket.org/2.0/workspaces", {'role': 'member'}
        )
        while next_page:
            resp_json = await self.httpfetch(next_page, method="GET", headers=headers)
            next_page = resp_json.get('next', None)

            user_teams = {entry["name"] for entry in resp_json["values"]}
            if any(user_teams & self.allowed_team):
                return True
        return False


class LocalBitbucketOAuthenticator(LocalAuthenticator, BitbucketOAuthenticator):
    """A version that mixes in local system user creation"""
