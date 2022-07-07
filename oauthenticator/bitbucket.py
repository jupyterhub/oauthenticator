"""
Custom Authenticator to use Bitbucket OAuth with JupyterHub
"""
from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import Set, default

from .oauth2 import OAuthenticator


class BitbucketOAuthenticator(OAuthenticator):

    _deprecated_oauth_aliases = {
        "team_whitelist": ("allowed_teams", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "Bitbucket"
    client_id_env = 'BITBUCKET_CLIENT_ID'
    client_secret_env = 'BITBUCKET_CLIENT_SECRET'

    @default("user_auth_state_key")
    def _user_auth_state_key_default(self):
        return "bitbucket_user"

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

        # Check if user is a member of any allowed teams.
        # This check is performed here, as the check requires `access_token`.
        if self.allowed_teams:
            user_in_team = await self._check_membership_allowed_teams(
                username, access_token, token_type
            )
            if not user_in_team:
                self.log.warning("%s not in team allowed list of users", username)
                return False

        return True

    async def _check_membership_allowed_teams(self, username, access_token, token_type):
        headers = self.build_userdata_request_headers(access_token, token_type)
        # We verify the team membership by calling teams endpoint.
        next_page = url_concat(
            "https://api.bitbucket.org/2.0/workspaces", {'role': 'member'}
        )
        while next_page:
            req = HTTPRequest(next_page, method="GET", headers=headers)
            resp_json = await self.fetch(req)
            next_page = resp_json.get('next', None)

            user_teams = set([entry["name"] for entry in resp_json["values"]])
            # check if any of the organizations seen thus far are in the allowed list
            if len(self.allowed_teams & user_teams) > 0:
                return True
        return False


class LocalBitbucketOAuthenticator(LocalAuthenticator, BitbucketOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
