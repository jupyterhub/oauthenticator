"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)

Extended use of GH attributes (uid/gid, email, save-token) by Adam Thornton
 (athornton@lsst.org)
"""


import json
import os
import re
import string

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Set

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com'
else:
    GITHUB_API = '%s/api/v3' % GITHUB_HOST


def _api_headers(access_token):
    return {"Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "token {}".format(access_token)
            }


class GitHubMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/login/oauth/authorize" % GITHUB_HOST
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/login/oauth/access_token" % GITHUB_HOST


class GitHubLoginHandler(OAuthLoginHandler, GitHubMixin):
    """We check the environment variables GITHUB_USE_ORGANIZATIONS,
    GITHUB_USE_PUSH_TOKEN, GITHUB_USE_PRIVATE_PUSH_TOKEN, and
    GITHUB_USE_EMAIL in order to set up the scope for the token we
    request.

    Each of these turns on a feature if it is set.

    GITHUB_USE_ORGANIZATIONS enables the use of GitHub organizations
    to allow provisioning of backend gids, which requires "read:org"
    scope to iterate through the user's organizations and map their
    names to their id numbers.

    GITHUB_USE_PUSH_TOKEN requests "public_repo" access in order to
    push code into public repositories--we use magic on the backend to
    cache the GitHub token and set up .git-credentials with it.

    GITHUB_USE_PRIVATE_PUSH_TOKEN does the same but with "repo"
    access, so it can access both public and private repositories.

    GITHUB_USE_EMAIL looks at the GitHub email field; this is used to
    set up the user email address for GitHub in conjunction with the
    push token.  It uses "user:email" scope but it's less than useful
    since private email addresses are still not visible.

    These are all stored in the authenticator's `auth_state`
    structure, so you'll need to enable `auth_state` and install the
    Python `cryptography` package to be able to use these.

    You will also need to subclass your spawner to be able to pull
    these fields out of `auth_state` and use them to provision your
    Notebook or Lab user.

    """

    use_organizations = False
    use_push_token = False
    use_private_push_token = False
    use_email = False

    if os.environ.get('GITHUB_USE_ORGANIZATIONS'):
        use_organizations = True
    if os.environ.get('GITHUB_USE_PUSH_TOKEN'):
        use_push_token = True
    if os.environ.get('GITHUB_USE_PRIVATE_PUSH_TOKEN'):
        use_private_push_token = True
    if os.environ.get('GITHUB_USE_EMAIL'):
        use_email = True
    scope = []
    if use_organizations:
        scope.append("read:org")
    if use_private_push_token:
        scope.append("repo")
    elif use_push_token:
        scope.append("public_repo")
    if use_email:
        scope.append("user:email")


class GitHubOAuthenticator(OAuthenticator):

    login_service = "GitHub"

    # deprecated names
    github_client_id = Unicode(config=True, help="DEPRECATED")

    def _github_client_id_changed(self, name, old, new):
        self.log.warn("github_client_id is deprecated, use client_id")
        self.client_id = new
    github_client_secret = Unicode(config=True, help="DEPRECATED")

    def _github_client_secret_changed(self, name, old, new):
        self.log.warn("github_client_secret is deprecated, use client_secret")
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

        url = url_concat("https://%s/login/oauth/access_token" % GITHUB_HOST,
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body=''  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        req = HTTPRequest("https://%s/user" % GITHUB_API,
                          method="GET",
                          headers=_api_headers(access_token)
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["login"]

        # Check if user is a member of any whitelisted organizations.
        # This check is performed here, as it requires `access_token`.
        if self.github_organization_whitelist:
            for org in self.github_organization_whitelist:
                user_in_org = yield self._check_organization_whitelist(org, username, access_token)
                if not user_in_org:
                    # User not found in member list for any organisation
                    return None
        # username is now the GitHub userid.
        if not username:
            return None
        userdict = {"name": username}
        # Now we set up auth_state
        auth_state = {}
        auth_state["username"] = username
        # We may want to do user provisioning in the server container.
        #  This next bit is about that.
        #  1) make the username look Unixy
        #  2) use the GitHub ID as the uid
        #  3) set list of orgs/gids
        #  4) set up name/email for .gitconfig
        safe_chars = set(string.ascii_lowercase + string.digits)
        safe_username = ''.join(
            [s if s in safe_chars else '-' for s in username.lower()])
        auth_state["canonicalname"] = safe_username
        auth_state["uid"] = resp_json["id"]
        auth_state["name"] = resp_json["name"]
        orgs = yield self._get_user_organizations(access_token)
        if orgs:
            auth_state["organization_map"] = orgs
        # Entirely possible "email" isn't present or is null.
        if "email" in resp_json and resp_json["email"]:
            auth_state["email"] = resp_json["email"]
        # Log authentication state (without token)
        auth_state["access_token"] = "[secret]"
        self.log.info("auth_state [%s]: %s" % (username,
                                               json.dumps(auth_state,
                                                          indent=4,
                                                          sort_keys=True)))
        auth_state["access_token"] = access_token
        userdict["auth_state"] = auth_state
        return userdict

    @gen.coroutine
    def _check_organization_whitelist(self, org, username, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        # Get all the members for organization 'org'
        next_page = "https://%s/orgs/%s/members" % (GITHUB_API, org)
        while next_page:
            req = HTTPRequest(next_page, method="GET", headers=headers)
            resp = yield http_client.fetch(req)
            resp_json = json.loads(resp.body.decode('utf8', 'replace'))
            next_page = next_page_from_links(resp)
            org_members = set(entry["login"] for entry in resp_json)
            # check if any of the organizations seen thus far are in whitelist
            if username in org_members:
                return True
        return False

    @gen.coroutine
    def _get_user_organizations(self, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        next_page = "https://%s/user/orgs" % (GITHUB_API)
        orgmap = {}
        while next_page:
            req = HTTPRequest(next_page, method="GET", headers=headers)
            resp = yield http_client.fetch(req)
            resp_json = json.loads(resp.body.decode('utf8', 'replace'))
            next_page = next_page_from_links(resp)
            for entry in resp_json:
                orgmap[entry["login"]] = entry["id"]
        return orgmap


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
