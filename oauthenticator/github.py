"""
A JupyterHub authenticator class for use with GitHub as an identity provider.
"""
import json
import os
import warnings

from jupyterhub.auth import LocalAuthenticator
from requests.utils import parse_header_links
from traitlets import Bool, Set, Unicode, default

from .oauth2 import OAuthenticator


class GitHubOAuthenticator(OAuthenticator):
    user_auth_state_key = "github_user"

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "GitHub")

    @default("username_claim")
    def _username_claim_default(self):
        return "login"

    github_url = Unicode(
        config=True,
        help="""
        Used to determine the default values for `github_api`, `authorize_url`,
        `token_url`, and `userdata_url`.
        """,
    )

    @default("github_url")
    def _github_url_default(self):
        github_url = os.environ.get("GITHUB_URL")
        if not github_url:
            # fallback on older GITHUB_HOST config,
            # treated the same as GITHUB_URL
            host = os.environ.get("GITHUB_HOST")
            if host:
                if os.environ.get("GITHUB_HTTP"):
                    protocol = "http"
                    warnings.warn(
                        "Use of GITHUB_HOST with GITHUB_HTTP might be deprecated in the future. "
                        f"Use GITHUB_URL=http://{host} to set host and protocol together.",
                        PendingDeprecationWarning,
                    )
                else:
                    protocol = "https"
                github_url = f"{protocol}://{host}"

        if github_url:
            if '://' not in github_url:
                # ensure protocol is included, assume https if missing
                github_url = 'https://' + github_url

            return github_url
        else:
            # nothing specified, this is the true default
            github_url = "https://github.com"

        # ensure no trailing slash
        return github_url.rstrip("/")

    github_api = Unicode(
        config=True,
        help="""
        URL to the GitHub REST API to use.

        Determined based on `github_url` by default and may never need to be
        explicitly set.
        """,
    )

    @default("github_api")
    def _github_api_default(self):
        if self.github_url == "https://github.com":
            return "https://api.github.com"
        else:
            # Only github.com has its api at api.github.com, enterprise server
            # deployments has it in the same domain path under /api/v3
            return self.github_url + "/api/v3"

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"{self.github_url}/login/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"{self.github_url}/login/oauth/access_token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"{self.github_api}/user"

    client_id_env = 'GITHUB_CLIENT_ID'
    client_secret_env = 'GITHUB_CLIENT_SECRET'

    allowed_organizations = Set(
        config=True,
        help="""
        Allow members of organizations or organizations' teams by specifying
        organization names like `org-a` and/or an organizations' team names like
        `org-b:team-1`.

        The names can have a human friendly variant with spaces etc, but you
        should specify the name as seen in a URL. As an example, it should be
        `jupyterhub:mybinder-org-operators` for the team
        https://github.com/orgs/jupyterhub/teams/mybinder-org-operators.

        Requires `read:org` to be set in `scope` to not just allow based on
        public membership.
        """,
    )

    populate_teams_in_auth_state = Bool(
        False,
        config=True,
        help="""
        Populates the authentication state dictionary `auth_state` with a key
        `teams` assigned the list of teams the current user is a member of at
        the time of authentication. The list of teams is structured like the
        response of the GitHub API documented in
        https://docs.github.com/en/rest/reference/teams#list-teams-for-the-authenticated-user.

        Requires `read:org` to be set in `scope`.
        
        Note that authentication state is only be available to a
        `post_auth_hook` before being discarded unless configured to be
        persisted via `enable_auth_state`. For more information, see
        https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#authentication-state.
        """,
    )

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "github_client_id": ("client_id", "0.1.0"),
        "github_client_secret": ("client_secret", "0.1.0"),
        "github_organization_whitelist": ("allowed_organizations", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    github_client_id = Unicode(
        config=True,
        help="""
        .. deprecated:: 0.1

           Use :attr:`client_id`.
        """,
    )
    github_client_secret = Unicode(
        config=True,
        help="""
        .. deprecated:: 0.1

           Use :attr:`client_secret`.
        """,
    )
    github_organization_whitelist = Set(
        config=True,
        help="""
        .. deprecated:: 0.12

           Use :attr:`allowed_organizations`.
        """,
    )

    async def check_allowed(self, username, auth_model):
        """
        Overrides the OAuthenticator.check_allowed to also allow users part of
        `allowed_organizations`.
        """
        if await super().check_allowed(username, auth_model):
            return True

        if self.allowed_organizations:
            access_token = auth_model["auth_state"]["token_response"]["access_token"]
            token_type = auth_model["auth_state"]["token_response"]["token_type"]
            for org_team in self.allowed_organizations:
                if await self._check_membership_allowed_organizations(
                    org_team, username, access_token, token_type
                ):
                    return True
            message = f"User {username} is not part of allowed_organizations"
            self.log.warning(message)

        # users should be explicitly allowed via config, otherwise they aren't
        return False

    async def update_auth_model(self, auth_model):
        """
        Fetch and store `email` in auth state if the user's only was: private,
        not part of the initial response, and we was granted a scope to fetch
        the private email.

        Also fetch and store `teams` in auth state if
        `populate_teams_in_auth_state` is configured.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]

        # If a public email is not available, an extra API call has to be made
        # to a /user/emails using the access token to retrieve emails. The
        # scopes relevant for this are checked based on this documentation:
        # - about scopes: https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps#available-scopes
        # - about /user/emails: https://docs.github.com/en/rest/reference/users#list-email-addresses-for-the-authenticated-user
        #
        # Note that the read:user scope does not imply the user:emails scope!
        access_token = auth_model["auth_state"]["token_response"]["access_token"]
        token_type = auth_model["auth_state"]["token_response"]["token_type"]
        granted_scopes = auth_model["auth_state"].get("scope", [])
        if not user_info["email"] and (
            "user" in granted_scopes or "user:email" in granted_scopes
        ):
            resp_json = await self.httpfetch(
                f"{self.github_api}/user/emails",
                "fetching user emails",
                method="GET",
                headers=self.build_userdata_request_headers(access_token, token_type),
                validate_cert=self.validate_server_cert,
            )
            for val in resp_json:
                if val["primary"]:
                    user_info["email"] = val["email"]
                    break

        if self.populate_teams_in_auth_state:
            if "read:org" not in self.scope:
                # This means the "read:org" scope was not set, and we can't
                # fetch teams
                self.log.error(
                    "read:org scope is required for populate_teams_in_auth_state functionality to work"
                )
            else:
                # https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user
                url = f"{self.github_api}/user/teams?per_page=100"
                user_teams = await self._paginated_fetch(url, access_token, token_type)
                auth_model["auth_state"]["teams"] = user_teams

        return auth_model

    async def _paginated_fetch(self, api_url, access_token, token_type):
        """
        Fetch all items via a paginated GitHub API call

        Makes a request to api_url, and if pagination information is returned,
        keep paginating until all the items are retrieved.
        """
        url = api_url
        content = []
        while True:
            resp = await self.httpfetch(
                url,
                "fetching user teams",
                parse_json=False,
                method="GET",
                headers=self.build_userdata_request_headers(access_token, token_type),
                validate_cert=self.validate_server_cert,
            )

            resp_json = json.loads(resp.body.decode())
            content += resp_json

            # Check if a Link header is present, with a collection of pagination links
            links_header = resp.headers.get('Link')
            if not links_header:
                # If Link header is not present, we just exit
                break

            # If Link header is present, let's parse it.
            links = parse_header_links(links_header)

            next_url = None
            # Look through all links to see if there is a 'next' link present
            for l in links:
                if l.get('rel') == 'next':
                    next_url = l['url']
                    break

            # If we found a 'next' link, continue the while loop with the new URL
            # If not, we're out of pages to paginate, so we stop
            if next_url is not None:
                url = next_url
            else:
                break
        return content

    async def _check_membership_allowed_organizations(
        self, org_team, username, access_token, token_type
    ):
        """
        Checks if a user is part of an organization or organization's team via
        GitHub's REST API. The `read:org` scope is required to not only check
        for public org/team membership.

        The `org_team` parameter accepts values like `org-a` or `org-b:team-1`,
        and will adjust to use a the relevant REST API to check either org or
        team membership.
        """
        headers = self.build_userdata_request_headers(access_token, token_type)

        if ":" in org_team:
            # check if user is part of an organization's team
            # https://docs.github.com/en/rest/teams/members?apiVersion=2022-11-28#get-team-member-legacy
            org, team = org_team.split(":")
            api_url = f"{self.github_api}/orgs/{org}/teams/{team}/members/{username}"
        else:
            # check if user is part of an organization
            # https://docs.github.com/en/rest/orgs/members?apiVersion=2022-11-28#check-organization-membership-for-a-user
            org = org_team
            api_url = f"{self.github_api}/orgs/{org}/members/{username}"

        self.log.debug(f"Checking GitHub organization membership: {username} in {org}?")
        resp = await self.httpfetch(
            api_url,
            parse_json=False,
            raise_error=False,
            method="GET",
            headers=headers,
            validate_cert=self.validate_server_cert,
        )
        if resp.code == 204:
            self.log.debug(f"Allowing {username} as member of {org_team}")
            return True
        else:
            try:
                resp_json = json.loads((resp.body or b'').decode('utf8', 'replace'))
                message = resp_json.get('message', '')
            except ValueError:
                message = ''
            self.log.debug(
                f"{username} does not appear to be a member of {org_team} (status={resp.code}): {message}",
            )
        return False


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):
    """A version that mixes in local system user creation"""
