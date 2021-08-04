"""
Authenticator to use GitHub OAuth with JupyterHub
"""
import json
import os
import warnings

from jupyterhub.auth import LocalAuthenticator
from tornado import web
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import default
from traitlets import Set
from traitlets import Unicode

from .oauth2 import OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "token {}".format(access_token),
    }


class GitHubOAuthenticator(OAuthenticator):

    # see github_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.GitHubOAuthenticator.scope = ['read:org']

    _deprecated_oauth_aliases = {
        "github_organization_whitelist": ("allowed_organizations", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "GitHub"

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

    async def authenticate(self, handler, data=None):
        """We set up auth_state based on additional GitHub info if we
        receive it.
        """
        code = handler.get_argument("code")

        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/

        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id, client_secret=self.client_secret, code=code
        )

        url = url_concat(self.token_url, params)

        req = HTTPRequest(
            url,
            method="POST",
            headers={"Accept": "application/json"},
            body='',  # Body is required for a POST...
            validate_cert=self.validate_server_cert,
        )

        resp_json = await self.fetch(req)

        if 'access_token' in resp_json:
            access_token = resp_json['access_token']
        elif 'error_description' in resp_json:
            raise web.HTTPError(
                403,
                "An access token was not returned: {}".format(
                    resp_json['error_description']
                ),
            )
        else:
            raise web.HTTPError(500, "Bad response: {}".format(resp_json))

        granted_scopes = []
        if resp_json.get("scope"):
            granted_scopes = resp_json["scope"].split(",")

        # Determine who the logged-in user is
        req = HTTPRequest(
            self.github_api + "/user",
            method="GET",
            headers=_api_headers(access_token),
            validate_cert=self.validate_server_cert,
        )
        resp_json = await self.fetch(req, "fetching user info")

        username = resp_json["login"]
        # username is now the GitHub userid.
        if not username:
            return None
        # Check if user is a member of any allowed organizations.
        # This check is performed here, as it requires `access_token`.
        if self.allowed_organizations:
            for org in self.allowed_organizations:
                user_in_org = await self._check_membership_allowed_organizations(
                    org, username, access_token
                )
                if user_in_org:
                    break
            else:  # User not found in member list for any organisation
                self.log.warning("User %s is not in allowed org list", username)
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
        # If a public email is not available, an extra API call has to be made
        # to a /user/emails using the access token to retrieve emails. The
        # scopes relevant for this are checked based on this documentation:
        # - about scopes: https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps#available-scopes
        # - about /user/emails: https://docs.github.com/en/rest/reference/users#list-email-addresses-for-the-authenticated-user
        #
        # Note that the read:user scope does not imply the user:emails scope!
        if not auth_state['github_user']['email'] and (
            'user' in granted_scopes or 'user:email' in granted_scopes
        ):
            req = HTTPRequest(
                self.github_api + "/user/emails",
                method="GET",
                headers=_api_headers(access_token),
                validate_cert=self.validate_server_cert,
            )
            resp_json = await self.fetch(req, "fetching user emails")
            for val in resp_json:
                if val["primary"]:
                    auth_state['github_user']['email'] = val['email']
                    break

        return userdict

    async def _check_membership_allowed_organizations(
        self, org, username, access_token
    ):
        headers = _api_headers(access_token)
        # Check membership of user `username` for organization `org` via api [check-membership](https://developer.github.com/v3/orgs/members/#check-membership)
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
