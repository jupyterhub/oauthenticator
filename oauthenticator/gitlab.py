"""
Custom Authenticator to use GitLab OAuth with JupyterHub
"""


import json
import os
import re
import sys
import warnings
from urllib.parse import quote

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.escape import url_escape
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set, CUnicode, Unicode, default, observe

from .oauth2 import OAuthLoginHandler, OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "Bearer {}".format(access_token),
    }


class GitLabOAuthenticator(OAuthenticator):
    # see gitlab_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.GitLabOAuthenticator.scope = ['read_user']

    _deprecated_oauth_aliases = {
        "gitlab_group_whitelist": ("allowed_gitlab_groups", "0.12.0"),
        "gitlab_project_id_whitelist": ("allowed_project_ids", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "GitLab"

    client_id_env = 'GITLAB_CLIENT_ID'
    client_secret_env = 'GITLAB_CLIENT_SECRET'

    gitlab_url = Unicode("https://gitlab.com", config=True)

    @default("gitlab_url")
    def _default_gitlab_url(self):
        """get default gitlab url from env"""
        gitlab_url = os.getenv('GITLAB_URL')
        gitlab_host = os.getenv('GITLAB_HOST')

        if not gitlab_url and gitlab_host:
            warnings.warn(
                'Use of GITLAB_HOST might be deprecated in the future. '
                'Rename GITLAB_HOST environment variable to GITLAB_URL.',
                PendingDeprecationWarning,
            )
            if gitlab_host.startswith(('https:', 'http:')):
                gitlab_url = gitlab_host
            else:
                # Hides common mistake of users which set the GITLAB_HOST
                # without a protocol specification.
                gitlab_url = 'https://{0}'.format(gitlab_host)
                warnings.warn(
                    'The https:// prefix has been added to GITLAB_HOST.'
                    'Set GITLAB_URL="{0}" instead.'.format(gitlab_host)
                )

        # default to gitlab.com
        if not gitlab_url:
            gitlab_url = 'https://gitlab.com'

        return gitlab_url

    gitlab_api_version = CUnicode('4', config=True)

    @default('gitlab_api_version')
    def _gitlab_api_version_default(self):
        return os.environ.get('GITLAB_API_VERSION') or '4'

    gitlab_api = Unicode(config=True)

    @default("gitlab_api")
    def _default_gitlab_api(self):
        return '%s/api/v%s' % (self.gitlab_url, self.gitlab_api_version)

    @default("authorize_url")
    def _authorize_url_default(self):
        return "%s/oauth/authorize" % self.gitlab_url

    @default("token_url")
    def _token_url_default(self):
        return "%s/oauth/access_token" % self.gitlab_url

    gitlab_group_whitelist = Set(help="Deprecated, use `GitLabOAuthenticator.allowed_gitlab_groups`", config=True,)

    allowed_gitlab_groups = Set(
        config=True, help="Automatically allow members of selected groups"
    )

    gitlab_project_id_whitelist = Set(help="Deprecated, use `GitLabOAuthenticator.allowed_project_ids`", config=True,)

    allowed_project_ids = Set(
        config=True,
        help="Automatically allow members with Developer access to selected project ids",
    )

    gitlab_version = None

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

        url = url_concat("%s/oauth/token" % self.gitlab_url, params)

        req = HTTPRequest(
            url,
            method="POST",
            headers={"Accept": "application/json"},
            validate_cert=validate_server_cert,
            body='',  # Body is required for a POST...
        )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # memoize gitlab version for class lifetime
        if self.gitlab_version is None:
            self.gitlab_version = await self._get_gitlab_version(access_token)
            self.member_api_variant = 'all/' if self.gitlab_version >= [12, 4] else ''

        # Determine who the logged in user is
        req = HTTPRequest(
            "%s/user" % self.gitlab_api,
            method="GET",
            validate_cert=validate_server_cert,
            headers=_api_headers(access_token),
        )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["username"]
        user_id = resp_json["id"]
        is_admin = resp_json.get("is_admin", False)

        # Check if user is a member of any allowed groups or projects.
        # These checks are performed here, as it requires `access_token`.
        user_in_group = user_in_project = False
        is_group_specified = is_project_id_specified = False

        if self.allowed_gitlab_groups:
            is_group_specified = True
            user_in_group = await self._check_membership_allowed_groups(user_id, access_token)

        # We skip project_id check if user is in allowed group.
        if self.allowed_project_ids and not user_in_group:
            is_project_id_specified = True
            user_in_project = await self._check_membership_allowed_project_ids(
                user_id, access_token
            )

        no_config_specified = not (is_group_specified or is_project_id_specified)

        if (
            (is_group_specified and user_in_group)
            or (is_project_id_specified and user_in_project)
            or no_config_specified
        ):
            return {
                'name': username,
                'auth_state': {'access_token': access_token, 'gitlab_user': resp_json},
            }
        else:
            self.log.warning("%s not in group or project allowed list", username)
            return None

    async def _get_gitlab_version(self, access_token):
        url = '%s/version' % self.gitlab_api
        req = HTTPRequest(
            url,
            method="GET",
            headers=_api_headers(access_token),
            validate_cert=self.validate_server_cert,
        )
        resp = await AsyncHTTPClient().fetch(req, raise_error=True)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        version_strings = resp_json['version'].split('-')[0].split('.')[:3]
        version_ints = list(map(int, version_strings))
        return version_ints

    async def _check_membership_allowed_groups(self, user_id, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        # Check if user is a member of any group in the allowed list
        for group in map(url_escape, self.allowed_gitlab_groups):
            url = "%s/groups/%s/members/%s%d" % (
                self.gitlab_api,
                quote(group, safe=''),
                self.member_api_variant,
                user_id,
            )
            req = HTTPRequest(url, method="GET", headers=headers)
            resp = await http_client.fetch(req, raise_error=False)
            if resp.code == 200:
                return True  # user _is_ in group
        return False

    async def _check_membership_allowed_project_ids(self, user_id, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        # Check if user has developer access to any project in the allowed list
        for project in self.allowed_project_ids:
            url = "%s/projects/%s/members/%s%d" % (
                self.gitlab_api,
                project,
                self.member_api_variant,
                user_id,
            )
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
