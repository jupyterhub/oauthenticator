"""
Custom Authenticator to use Bitbucket OAuth with JupyterHub
"""
import urllib

from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import default
from traitlets import Set

from .oauth2 import OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "Bearer {}".format(access_token),
    }


class BitbucketOAuthenticator(OAuthenticator):

    _deprecated_oauth_aliases = {
        "team_whitelist": ("allowed_teams", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "Bitbucket"
    client_id_env = 'BITBUCKET_CLIENT_ID'
    client_secret_env = 'BITBUCKET_CLIENT_SECRET'

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://bitbucket.org/site/oauth2/authorize"

    @default("token_url")
    def _token_url_default(self):
        return "https://bitbucket.org/site/oauth2/access_token"

    team_whitelist = Set(
        help="Deprecated, use `BitbucketOAuthenticator.allowed_teams`",
        config=True,
    )

    allowed_teams = Set(
        config=True, help="Automatically allow members of selected teams"
    )

    headers = {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "Bearer {}",
    }

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="authorization_code",
            code=code,
            redirect_uri=self.get_callback_url(handler),
        )

        url = url_concat("https://bitbucket.org/site/oauth2/access_token", params)

        bb_header = {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}
        req = HTTPRequest(
            url,
            method="POST",
            auth_username=self.client_id,
            auth_password=self.client_secret,
            body=urllib.parse.urlencode(params).encode('utf-8'),
            headers=bb_header,
        )

        resp_json = await self.fetch(req)

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        req = HTTPRequest(
            "https://api.bitbucket.org/2.0/user",
            method="GET",
            headers=_api_headers(access_token),
        )
        resp_json = await self.fetch(req)

        username = resp_json["username"]

        # Check if user is a member of any allowed teams.
        # This check is performed here, as the check requires `access_token`.
        if self.allowed_teams:
            user_in_team = await self._check_membership_allowed_teams(
                username, access_token
            )
            if not user_in_team:
                self.log.warning("%s not in team allowed list of users", username)
                return None

        return {
            'name': username,
            'auth_state': {'access_token': access_token, 'bitbucket_user': resp_json},
        }

    async def _check_membership_allowed_teams(self, username, access_token):

        headers = _api_headers(access_token)
        # We verify the team membership by calling teams endpoint.
        next_page = url_concat(
            "https://api.bitbucket.org/2.0/teams", {'role': 'member'}
        )
        while next_page:
            req = HTTPRequest(next_page, method="GET", headers=headers)
            resp_json = await self.fetch(req)
            next_page = resp_json.get('next', None)

            user_teams = set([entry["username"] for entry in resp_json["values"]])
            # check if any of the organizations seen thus far are in the allowed list
            if len(self.allowed_teams & user_teams) > 0:
                return True
        return False


class LocalBitbucketOAuthenticator(LocalAuthenticator, BitbucketOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
