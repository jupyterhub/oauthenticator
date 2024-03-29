"""
A JupyterHub authenticator class for use with GitLab as an identity provider.
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
    user_auth_state_key = "gitlab_user"
    client_id_env = 'GITLAB_CLIENT_ID'
    client_secret_env = 'GITLAB_CLIENT_SECRET'

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "GitLab")

    gitlab_url = Unicode(
        config=True,
        help="""
        Used to determine the default values for `gitlab_api`, `authorize_url`,
        `token_url`.
        """,
    )

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

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"{self.gitlab_url}/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"{self.gitlab_url}/oauth/token"

    gitlab_api_version = CUnicode(
        config=True,
        help="""
        Used to determine the default values for `gitlab_api`.

        For details, see https://docs.gitlab.com/ee/api/rest/.
        """,
    )

    @default("gitlab_api_version")
    def _gitlab_api_version_default(self):
        return os.environ.get("GITLAB_API_VERSION") or "4"

    gitlab_api = Unicode(
        config=True,
        help="""
        Used to determine the default value for `userdata_url`.
        """,
    )

    @default("gitlab_api")
    def _default_gitlab_api(self):
        return f"{self.gitlab_url}/api/v{self.gitlab_api_version}"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"{self.gitlab_api}/user"

    allowed_gitlab_groups = Set(
        config=True,
        help="""
        Allow members of selected GitLab groups to sign in.

        Note that for each group allowed, an additional REST API call needs to
        be made when a user is signing in. To reduce the risk of JupyterHub
        being rate limited, don't specify too many.
        """,
    )

    allowed_project_ids = Set(
        config=True,
        help="""
        Allow members with Developer access or higher in selected project ids to
        sign in.

        Note that for each project allowed, an additional REST API call needs to
        be made when a user is signing in. To reduce the risk of JupyterHub
        being rate limited, don't specify too many.
        """,
    )

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "gitlab_group_whitelist": ("allowed_gitlab_groups", "0.12.0"),
        "gitlab_project_id_whitelist": ("allowed_project_ids", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    gitlab_group_whitelist = Set(
        config=True,
        help="""
        .. deprecated:: 0.12

           Use :attr:`allowed_gitlab_groups`.
        """,
    )
    gitlab_project_id_whitelist = Set(
        config=True,
        help="""
        .. deprecated:: 0.12

           Use :attr:`allowed_project_ids`.
        """,
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
        Overrides the OAuthenticator.check_allowed to also allow users part of
        `allowed_google_groups` or `allowed_project_ids`.
        """
        if await super().check_allowed(username, auth_model):
            return True

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

        # users should be explicitly allowed via config, otherwise they aren't
        return False

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
        await self._set_gitlab_version(access_token)

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
        await self._set_gitlab_version(access_token)

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
