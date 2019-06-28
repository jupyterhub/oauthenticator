"""
Custom Authenticator to use GitLab OAuth with JupyterHub

Modified for GitLab by Laszlo Dobos (@dobos)
based on the GitHub plugin by Kyle Kelley (@rgbkrk)
"""


import json
import os
import sys
import warnings

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.escape import url_escape
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set

from .oauth2 import OAuthLoginHandler, OAuthenticator

GITLAB_URL = os.getenv('GITLAB_URL')
GITLAB_HOST = os.getenv('GITLAB_HOST')

if not GITLAB_URL and GITLAB_HOST:
    warnings.warn('Use of GITLAB_HOST might be deprecated in the future. '
                  'Rename GITLAB_HOST environemnt variable to GITLAB_URL.',
                  PendingDeprecationWarning)
    if GITLAB_HOST.startswith('https://') or GITLAB_HOST.startswith('http://'):
        GITLAB_URL = GITLAB_HOST
    else:
        # Hides common mistake of users which set the GITLAB_HOST
        # without a protocol specification.
        GITLAB_URL = 'https://{0}'.format(GITLAB_HOST)
        warnings.warn('The https:// prefix has been added to GITLAB_HOST.'
                      'Set GITLAB_URL="{0}" instead.'.format(GITLAB_URL))

# Support gitlab.com and gitlab community edition installations
if not GITLAB_URL:
    GITLAB_URL = 'https://gitlab.com'

# Use only GITLAB_URL in the code bellow.
del GITLAB_HOST

GITLAB_API_VERSION = os.environ.get('GITLAB_API_VERSION') or '4'
GITLAB_API = '%s/api/v%s' % (GITLAB_URL, GITLAB_API_VERSION)


def _api_headers(access_token):
    return {"Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token)
           }


class GitLabMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "%s/oauth/authorize" % GITLAB_URL
    _OAUTH_ACCESS_TOKEN_URL = "%s/oauth/access_token" % GITLAB_URL


class GitLabLoginHandler(OAuthLoginHandler, GitLabMixin):
    pass


class GitLabOAuthenticator(OAuthenticator):
    # see gitlab_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.GitLabOAuthenticator.scope = ['read_user']

    login_service = "GitLab"

    client_id_env = 'GITLAB_CLIENT_ID'
    client_secret_env = 'GITLAB_CLIENT_SECRET'
    login_handler = GitLabLoginHandler

    gitlab_group_whitelist = Set(
        config=True,
        help="Automatically whitelist members of selected groups",
    )
    gitlab_project_id_whitelist = Set(
        config=True,
        help="Automatically whitelist members with Developer access to selected project ids",
    )


    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a GitLab Access Token
        #
        # See: https://github.com/gitlabhq/gitlabhq/blob/master/doc/api/oauth2.md

        # GitLab specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            grant_type="authorization_code",
            redirect_uri=self.get_callback_url(handler),
        )


        validate_server_cert = self.validate_server_cert

        url = url_concat("%s/oauth/token" % GITLAB_URL,
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          validate_cert=validate_server_cert,
                          body='' # Body is required for a POST...
                          )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        req = HTTPRequest("%s/user" % GITLAB_API,
                          method="GET",
                          validate_cert=validate_server_cert,
                          headers=_api_headers(access_token)
                          )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["username"]
        user_id = resp_json["id"]
        is_admin = resp_json.get("is_admin", False)

        # Check if user is a member of any whitelisted groups or projects.
        # These checks are performed here, as it requires `access_token`.
        user_in_group = user_in_project = False
        is_group_specified = is_project_id_specified = False

        if self.gitlab_group_whitelist:
            is_group_specified = True
            user_in_group = await self._check_group_whitelist(user_id, access_token)

        # We skip project_id check if user is in whitelisted group.
        if self.gitlab_project_id_whitelist and not user_in_group:
            is_project_id_specified = True
            user_in_project = await self._check_project_id_whitelist(user_id, access_token)

        no_config_specified = not (is_group_specified or is_project_id_specified)

        if (is_group_specified and user_in_group) or \
            (is_project_id_specified and user_in_project) or \
                no_config_specified:
            return {
                'name': username,
                'auth_state': {
                    'access_token': access_token,
                    'gitlab_user': resp_json,
                }
            }
        else:
            self.log.warning("%s not in group or project whitelist", username)
            return None


    async def _check_group_whitelist(self, user_id, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        # Check if user is a member of any group in the whitelist
        for group in map(url_escape, self.gitlab_group_whitelist):
            url = "%s/groups/%s/members/%d" % (GITLAB_API, group, user_id)
            req = HTTPRequest(url, method="GET", headers=headers)
            resp = await http_client.fetch(req, raise_error=False)
            if resp.code == 200:
                return True  # user _is_ in group
        return False


    async def _check_project_id_whitelist(self, user_id, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        # Check if user has developer access to any project in the whitelist
        for project in self.gitlab_project_id_whitelist:
            url = "%s/projects/%s/members/%d" % (GITLAB_API, project, user_id)
            req = HTTPRequest(url, method="GET", headers=headers)
            resp = await http_client.fetch(req, raise_error=False)

            if resp.body:
                resp_json = json.loads(resp.body.decode('utf8', 'replace'))
                access_level = resp_json.get('access_level', 0)

                # We only allow access level Developer and above
                # Reference: https://docs.gitlab.com/ee/api/members.html
                if resp.code == 200 and access_level >= 30:
                    return True
        return False


class LocalGitLabOAuthenticator(LocalAuthenticator, GitLabOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
