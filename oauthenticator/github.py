"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)

Extended use of GH attributes by Adam Thornton (athornton@lsst.org)
"""


import json
import os
import re
import string

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError

from jupyterhub.auth import LocalAuthenticator

from traitlets import List, Set, Unicode

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com'
else:
    GITHUB_API = '%s/api/v3' % GITHUB_HOST

# Support github enterprise installations with both http and https
GITHUB_HTTP = os.environ.get('GITHUB_HTTP')
if GITHUB_HTTP:
    GITHUB_PROTOCOL = 'http'
else:
    GITHUB_PROTOCOL = 'https'

def _api_headers(access_token):
    return {"Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "token {}".format(access_token)
            }


class GitHubMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "%s://%s/login/oauth/authorize" % (GITHUB_PROTOCOL, GITHUB_HOST)
    _OAUTH_ACCESS_TOKEN_URL = "%s://%s/login/oauth/access_token" % (GITHUB_PROTOCOL, GITHUB_HOST)


class GitHubLoginHandler(OAuthLoginHandler, GitHubMixin):
    pass


class GitHubOAuthenticator(OAuthenticator):

    # see github_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.GitHubOAuthenticator.scope = ['read:org']

    login_service = "GitHub"

    # deprecated names
    github_client_id = Unicode(config=True, help="DEPRECATED")

    def _github_client_id_changed(self, name, old, new):
        self.log.warning("github_client_id is deprecated, use client_id")
        self.client_id = new
    github_client_secret = Unicode(config=True, help="DEPRECATED")

    def _github_client_secret_changed(self, name, old, new):
        self.log.warning("github_client_secret is deprecated, use client_secret")
        self.client_secret = new

    client_id_env = 'GITHUB_CLIENT_ID'
    client_secret_env = 'GITHUB_CLIENT_SECRET'
    login_handler = GitHubLoginHandler

    github_organization_whitelist = Set(
        config=True,
        help="Automatically whitelist members of selected organizations",
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        """We set up auth_state based on additional GitHub info if we
        receive it.
        """
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/

        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code
        )

        url = url_concat("%s://%s/login/oauth/access_token" % (GITHUB_PROTOCOL, GITHUB_HOST),
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body=''  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if 'access_token' in resp_json:
            access_token = resp_json['access_token']
        elif 'error_description' in resp_json:
            raise HTTPError(403,
                "An access token was not returned: {}".format(
                    resp_json['error_description']))
        else:
            raise HTTPError(500,
                "Bad response: %s".format(resp))

        # Determine who the logged in user is
        req = HTTPRequest("%s://%s/user" % (GITHUB_PROTOCOL, GITHUB_API),
                          method="GET",
                          headers=_api_headers(access_token)
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["login"]
        # username is now the GitHub userid.
        if not username:
            return None
        # Check if user is a member of any whitelisted organizations.
        # This check is performed here, as it requires `access_token`.
        if self.github_organization_whitelist:
            for org in self.github_organization_whitelist:
                user_in_org = yield self._check_organization_whitelist(org, username, access_token)
                if user_in_org:
                    break
            else:  # User not found in member list for any organisation
                self.log.warning("User %s is not in org whitelist", username)
                return None
        userdict = {"name": username}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        # Save the access token and full GitHub reply (name, id, email) in auth state
        # These can be used for user provisioning in the Lab/Notebook environment.
        # e.g.
        #  1) stash the access token
        #  2) use the GitHub ID as the id
        #  3) set up name/email for .gitconfig
        auth_state['access_token'] = access_token
        # store the whole user model in auth_state.github_user
        auth_state['github_user'] = resp_json
        # A public email will return in the initial query (assuming default scope).
        # Private will not.

        return userdict

    @gen.coroutine
    def _check_whitelist(self, target, username, access_token):
        # Check if the user has permission against the target.

        # If target is specified with `:`, treat the latter part as level specifier.
        if ':' in target:
            target, level = target.split(':', 1)
        else:
            level = None

        if target.beginswith('orgs/'):
            # https://developer.github.com/v3/orgs/members/#check-membership
            # With empty scope (even if authenticated by an org member), this
            #  will only check public org members.  You want 'read:org' in order
            #  to be include private members.
            resp = yield self._call_github(target, username, 'members/{username}', access_token)
            if resp.get('state') != 'active':
                return False
            if level == 'admin':
                return resp.get('role') == 'admin'
            return True

        if target.beginswith('teams/'):
            # https://developer.github.com/v3/teams/members/#get-team-membership
            # Note that you need to specify team id rather than team name.
            # To find team id, use 'List teams' API (`GET /orgs/:org/teams`)
            resp = yield self._call_github(target, username, 'memberships/{username}', access_token)
            if resp.get('state') != 'active':
                return False
            if level == 'maintainer':
                return resp.get('role') == 'maintainer'
            return True

        if target.beginswith('repos/'):
            # https://developer.github.com/v3/orgs/members/#check-membership
            # You may need 'repo' scope.
            resp = yield self._call_github(target, username, 'collaborators/{username}/permission', access_token)
            permission = resp.get('permission', 'none')
            if level == 'admin':
                return permission == 'admin'
            if level == 'write':
                return permission in {'admin', 'write'}
            return level != 'none'

        self.log.warning("Unknown target '%s' specified. Must begins with 'orgs/', 'teams/' or 'repos/'", target)
        return False

    @gen.coroutine
    def _call_github(self, target, username, api_uri, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        url = "%s://%s/%s/%s" % (GITHUB_PROTOCOL, GITHUB_API, target, api_uri.format(username=username))
        req = HTTPRequest(url, method="GET", headers=headers)
        resp = yield http_client.fetch(req, raise_error=False)
        if resp.code != 404:
            resp.rethrow()
        if resp.code == 404 or not resp.body:
            return {}
        return json.loads(resp.body)


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
