"""
Authenticator to use GitHub OAuth with JupyterHub
"""
import json
import os
import warnings

from jupyterhub.auth import LocalAuthenticator
from requests.utils import parse_header_links
from tornado.httpclient import HTTPRequest
from traitlets import Bool, Set, Unicode, default

from .oauth2 import OAuthenticator


class GitHubOAuthenticator(OAuthenticator):

    # see github_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.GitHubOAuthenticator.scope = ['read:org']

    _deprecated_oauth_aliases = {
        "github_organization_whitelist": ("allowed_organizations", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "GitHub"

    @default("user_auth_state_key")
    def _user_auth_state_key_default(self):
        return "github_user"

    github_url = Unicode("https://github.com", config=True)

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
                        'Use of GITHUB_HOST with GITHUB_HTTP might be deprecated in the future. '
                        'Use GITHUB_URL=http://{} to set host and protocol together.'.format(
                            host
                        ),
                        PendingDeprecationWarning,
                    )
                else:
                    protocol = "https"
                github_url = "{}://{}".format(protocol, host)

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

    github_api = Unicode("https://api.github.com", config=True)

    @default("github_api")
    def _github_api_default(self):
        if self.github_url == "https://github.com":
            return "https://api.github.com"
        else:
            return self.github_url + "/api/v3"

    @default("authorize_url")
    def _authorize_url_default(self):
        return "%s/login/oauth/authorize" % (self.github_url)

    @default("token_url")
    def _token_url_default(self):
        return "%s/login/oauth/access_token" % (self.github_url)

    @default("userdata_url")
    def _userdata_url_default(self):
        return self.github_api + "/user"

    @default("username_claim")
    def _username_claim_default(self):
        return "login"

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

    github_organization_whitelist = Set(
        help="Deprecated, use `GitHubOAuthenticator.allowed_organizations`",
        config=True,
    )

    allowed_organizations = Set(
        config=True, help="Automatically allow members of selected organizations"
    )

    populate_teams_in_auth_state = Bool(
        False,
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
        config=True,
    )

    async def user_is_authorized(self, auth_model):
        # Check if user is a member of any allowed organizations.
        # This check is performed here, as it requires `access_token`.
        access_token = auth_model["auth_state"]["token_response"]["access_token"]
        token_type = auth_model["auth_state"]["token_response"]["token_type"]
        if self.allowed_organizations:
            for org in self.allowed_organizations:
                user_in_org = await self._check_membership_allowed_organizations(
                    org, auth_model["name"], access_token, token_type
                )
                if user_in_org:
                    break
            else:  # User not found in member list for any organisation
                self.log.warning(
                    "User %s is not in allowed org list", auth_model["name"]
                )
                return False

        return True

    async def update_auth_model(self, auth_model):
        # If a public email is not available, an extra API call has to be made
        # to a /user/emails using the access token to retrieve emails. The
        # scopes relevant for this are checked based on this documentation:
        # - about scopes: https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps#available-scopes
        # - about /user/emails: https://docs.github.com/en/rest/reference/users#list-email-addresses-for-the-authenticated-user
        #
        # Note that the read:user scope does not imply the user:emails scope!
        access_token = auth_model["auth_state"]["token_response"]["access_token"]
        token_type = auth_model["auth_state"]["token_response"]["token_type"]
        granted_scopes = []
        if auth_model["auth_state"]["scope"]:
            granted_scopes = auth_model["auth_state"]["scope"]

        if not auth_model["auth_state"]["github_user"]["email"] and (
            "user" in granted_scopes or "user:email" in granted_scopes
        ):
            req = HTTPRequest(
                self.github_api + "/user/emails",
                method="GET",
                headers=self.build_userdata_request_headers(access_token, token_type),
                validate_cert=self.validate_server_cert,
            )
            resp_json = await self.fetch(req, "fetching user emails")
            for val in resp_json:
                if val["primary"]:
                    auth_model["auth_state"]["github_user"]["email"] = val["email"]
                    break

        if self.populate_teams_in_auth_state:
            if "read:org" not in self.scope:
                # This means the "read:org" scope was not set, and we can"t fetch teams
                self.log.error(
                    "read:org scope is required for populate_teams_in_auth_state functionality to work"
                )
            else:
                # Number of teams to request per page
                per_page = 100

                #  https://docs.github.com/en/rest/reference/teams#list-teams-for-the-authenticated-user
                url = self.github_api + f"/user/teams?per_page={per_page}"

                auth_model["auth_state"]["teams"] = await self._paginated_fetch(
                    url, access_token, token_type
                )

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
            req = HTTPRequest(
                url,
                method="GET",
                headers=self.build_userdata_request_headers(access_token, token_type),
                validate_cert=self.validate_server_cert,
            )
            resp = await self.fetch(req, "fetching user teams", parse_json=False)

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
        self, org, username, access_token, token_type
    ):
        headers = self.build_userdata_request_headers(access_token, token_type)
        # Check membership of user `username` for organization `org` via api [check-membership](https://docs.github.com/en/rest/orgs/members#check-membership)
        # With empty scope (even if authenticated by an org member), this
        # will only await public org members.  You want 'read:org' in order
        # to be able to iterate through all members. If you would only like to
        # allow certain teams within an organisation, specify
        # allowed_organisations = {org_name:team_name}

        check_membership_url = self._build_check_membership_url(org, username)

        req = HTTPRequest(
            check_membership_url,
            method="GET",
            headers=headers,
            validate_cert=self.validate_server_cert,
        )
        self.log.debug(
            "Checking GitHub organization membership: %s in %s?", username, org
        )
        resp = await self.fetch(req, raise_error=False, parse_json=False)
        if resp.code == 204:
            self.log.info("Allowing %s as member of %s", username, org)
            return True
        else:
            try:
                resp_json = json.loads((resp.body or b'').decode('utf8', 'replace'))
                message = resp_json.get('message', '')
            except ValueError:
                message = ''
            self.log.debug(
                "%s does not appear to be a member of %s (status=%s): %s",
                username,
                org,
                resp.code,
                message,
            )
        return False

    def _build_check_membership_url(self, org: str, username: str) -> str:
        if ":" in org:
            org, team = org.split(":")
            return f"{self.github_api}/orgs/{org}/teams/{team}/members/{username}"
        else:
            return f"{self.github_api}/orgs/{org}/members/{username}"


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):

    """A version that mixes in local system user creation"""

    pass
