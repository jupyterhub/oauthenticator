"""
Custom Authenticator to use Bitbucket OAuth with JupyterHub
"""


import json
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set

from .oauth2 import OAuthLoginHandler, OAuthenticator

class BitbucketMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://bitbucket.org/site/oauth2/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"


class BitbucketLoginHandler(OAuthLoginHandler, BitbucketMixin):
    pass


class BitbucketOAuthenticator(OAuthenticator):

    login_service = "Bitbucket"
    client_id_env = 'BITBUCKET_CLIENT_ID'
    client_secret_env = 'BITBUCKET_CLIENT_SECRET'
    login_handler = BitbucketLoginHandler

    team_whitelist = Set(
        config=True,
        help="Automatically whitelist members of selected teams",
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="authorization_code",
            code=code,
            redirect_uri=self.oauth_callback_url
        )

        url = url_concat(
            "https://bitbucket.org/site/oauth2/access_token", params)
        self.log.info(url)

        bb_header = {"Content-Type":
                     "application/x-www-form-urlencoded;charset=utf-8"}
        req = HTTPRequest(url,
                          method="POST",
                          auth_username=self.client_id,
                          auth_password=self.client_secret,
                          body=urllib.parse.urlencode(params).encode('utf-8'),
                          headers=bb_header
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)
                   }
        req = HTTPRequest("https://api.bitbucket.org/2.0/user",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["username"]

    def check_whitelist(self, username, headers):
        if self.team_whitelist:
            return self._check_group_whitelist(username, headers)
        else:
            return self._check_user_whitelist(username)

    @gen.coroutine
    def _check_user_whitelist(self, user):
        return (not self.whitelist) or (user in self.whitelist)

    @gen.coroutine
    def _check_group_whitelist(self, username, headers):
        http_client = AsyncHTTPClient()

        # We verify the team membership by calling teams endpoint.
        # Re-use the headers, change the request.
        next_page = url_concat("https://api.bitbucket.org/2.0/teams",
                               {'role': 'member'})
        user_teams = set()
        while next_page:
            req = HTTPRequest(next_page, method="GET", headers=headers)
            resp = yield http_client.fetch(req)
            resp_json = json.loads(resp.body.decode('utf8', 'replace'))
            next_page = resp_json.get('next', None)

            user_teams |= \
                set([entry["username"] for entry in resp_json["values"]])
        return len(self.team_whitelist & user_teams) > 0


class LocalBitbucketOAuthenticator(LocalAuthenticator,
                                   BitbucketOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
