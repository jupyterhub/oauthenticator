"""
Custom Authenticator to use GitLab OAuth with JupyterHub
"""
import os
import warnings
from urllib.parse import quote

from jupyterhub.auth import LocalAuthenticator
from tornado.escape import url_escape
from traitlets import CUnicode, Set, Unicode, default

from .oauth2 import OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": f"Bearer {access_token}",
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
    user_auth_state_key = "gitlab_user"

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
                gitlab_url = f'https://{gitlab_host}'
                warnings.warn(
                    "The https:// prefix has been added to GITLAB_HOST. "
                    f'Set GITLAB_URL="{gitlab_host}" instead.'
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
        return f"{self.gitlab_url}/api/v{self.gitlab_api_version}"

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"{self.gitlab_url}/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"{self.gitlab_url}/oauth/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"{self.gitlab_api}/user"

    gitlab_group_whitelist = Set(
        help="Deprecated, use `GitLabOAuthenticator.allowed_gitlab_groups`",
        config=True,
    )

    allowed_gitlab_groups = Set(
        config=True, help="Automatically allow members of selected groups"
    )

    gitlab_project_id_whitelist = Set(
        help="Deprecated, use `GitLabOAuthenticator.allowed_project_ids`",
        config=True,
    )

    allowed_project_ids = Set(
        config=True,
        help="Automatically allow members with Developer access to selected project ids",
    )

    gitlab_version = None
    member_api_variant = None

    async def _set_gitlab_version(self, access_token):
        # memoize gitlab version for class lifetime
        if self.gitlab_version is None:
            self.gitlab_version = await self._get_gitlab_version(access_token)
            self.member_api_variant = 'all/' if self.gitlab_version >= [12, 4] else ''

    async def check_allowed(self, username, auth_model):
        """
        Returns True for users allowed to be authorized.

        Overrides the OAuthenticator.check_allowed implementation to allow users
        either part of `allowed_users` or `allowed_organizations`, and not just those
        part of `allowed_users`.
        """
        # allow admin users recognized via admin_users or update_auth_model
        if auth_model["admin"]:
            return True

        # if allowed_users or allowed_gitlab_groups or allowed_project_ids is configured,
        # we deny users not part of either
        if self.allowed_users or self.allowed_gitlab_groups or self.allowed_project_ids:
            if username in self.allowed_users:
                return True

            await self._set_gitlab_version(access_token)
            access_token = auth_model["auth_state"]["token_response"]["access_token"]
            user_id = auth_model["auth_state"][self.user_auth_state_key]["id"]

            if self.allowed_gitlab_groups:
                user_in_group = await self._check_membership_allowed_groups(
                    user_id, access_token
                )
                if user_in_group:
                    return True

            if self.allowed_project_ids:
                user_in_project = await self._check_membership_allowed_project_ids(
                    user_id, access_token
                )
                if user_in_project:
                    return True
            return False

        # otherwise, authorize all users
        return True

    async def _get_gitlab_version(self, access_token):
        url = f"{self.gitlab_api}/version"
        resp_json = await self.httpfetch(
            url,
            method="GET",
            headers=_api_headers(access_token),
            validate_cert=self.validate_server_cert,
        )
        version_strings = resp_json['version'].split('-')[0].split('.')[:3]
        version_ints = list(map(int, version_strings))
        return version_ints

    async def _check_membership_allowed_groups(self, user_id, access_token):
        headers = _api_headers(access_token)
        # Check if user is a member of any group in the allowed list
        for group in map(url_escape, self.allowed_gitlab_groups):
            url = "%s/groups/%s/members/%s%d" % (
                self.gitlab_api,
                quote(group, safe=''),
                self.member_api_variant,
                user_id,
            )
            resp = await self.httpfetch(
                url,
                parse_json=False,
                raise_error=False,
                method="GET",
                headers=headers,
                validate_cert=self.validate_server_cert,
            )
            if resp.code == 200:
                return True  # user _is_ in group
        return False

    async def _check_membership_allowed_project_ids(self, user_id, access_token):
        headers = _api_headers(access_token)
        # Check if user has developer access to any project in the allowed list
        for project in self.allowed_project_ids:
            url = "%s/projects/%s/members/%s%d" % (
                self.gitlab_api,
                project,
                self.member_api_variant,
                user_id,
            )
            resp_json = await self.httpfetch(
                url,
                raise_error=False,
                method="GET",
                headers=headers,
                validate_cert=self.validate_server_cert,
            )
            if resp_json:
                access_level = resp_json.get('access_level', 0)

                # We only allow access level Developer and above
                # Reference: https://docs.gitlab.com/ee/api/members.html
                if access_level >= 30:
                    return True
        return False


class LocalGitLabOAuthenticator(LocalAuthenticator, GitLabOAuthenticator):

    """A version that mixes in local system user creation"""
