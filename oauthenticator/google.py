"""
A JupyterHub authenticator class for use with Google as an identity provider.
"""

import os

from jupyterhub.auth import LocalAuthenticator
from tornado.auth import GoogleOAuth2Mixin
from tornado.web import HTTPError
from traitlets import Dict, List, Set, Unicode, default, validate

from .oauth2 import OAuthenticator


class GoogleOAuthenticator(OAuthenticator, GoogleOAuth2Mixin):
    user_auth_state_key = "google_user"

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "Google")

    @default("scope")
    def _scope_default(self):
        return ["openid", "email"]

    @default("username_claim")
    def _username_claim_default(self):
        return "email"

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://accounts.google.com/o/oauth2/v2/auth"

    google_api_url = Unicode(
        config=True,
        help="""
        Used to determine the default values for `token_url` and `userdata_url`.
        """,
    )

    @default("google_api_url")
    def _google_api_url(self):
        """get default google apis url from env"""
        google_api_url = os.getenv('GOOGLE_API_URL')

        # default to googleapis.com
        if not google_api_url:
            google_api_url = 'https://www.googleapis.com'

        return google_api_url

    @default("token_url")
    def _token_url_default(self):
        return f"{self.google_api_url}/oauth2/v4/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"{self.google_api_url}/oauth2/v1/userinfo"

    google_service_account_keys = Dict(
        Unicode(),
        config=True,
        help="""
        Service account keys to use with each domain, see https://developers.google.com/admin-sdk/directory/v1/guides/delegation

        Required if and only if `allowed_google_groups` or `admin_google_groups`
        is configured.
        """,
    )

    gsuite_administrator = Dict(
        Unicode(),
        config=True,
        help="""
        Username of a G Suite Administrator for the service account to act as.

        Required if and only if `allowed_google_groups` or `admin_google_groups`
        is configured.
        """,
    )

    allowed_google_groups = Dict(
        Set(Unicode()),
        config=True,
        help="""
        Allow members of selected Google groups to sign in.

        Use of this requires configuration of `gsuite_administrator` and
        `google_service_account_keys`.
        """,
    )

    admin_google_groups = Dict(
        Set(Unicode()),
        config=True,
        help="""
        Allow members of selected Google groups to sign in and consider them as
        JupyterHub admins.

        If this is set and a user isn't part of one of these groups or listed in
        `admin_users`, a user signing in will have their admin status revoked.

        Use of this requires configuration of `gsuite_administrator` and
        `google_service_account_keys`.
        """,
    )

    hosted_domain = List(
        Unicode(),
        config=True,
        help="""
        This config has two functions.

        1. Restrict sign-in to users part of Google organizations/workspaces
           managing domains, such as `["mycollege.edu"]` or `["college1.edu",
           "college2.edu"]`.
        2. If a single domain is specified, usernames with that domain will be
           stripped to exclude the `@domain` part.

        Users not restricted by this configuration must still be explicitly
        allowed by a configuration intended to allow users, like `allow_all`,
        `allowed_users`, or `allowed_google_groups`.

        .. warning::

           Changing this config either to or from having a single entry is a
           disruptive change as the same Google user will get a new username,
           either without or with a domain name included.

        .. versionchanged:: 16.1

           Now restricts sign-in based on the hd claim, not the domain in the
           user's email.
        """,
    )

    @default('hosted_domain')
    def _hosted_domain_from_env(self):
        domains = []
        for domain in os.environ.get('HOSTED_DOMAIN', '').lower().split(';'):
            if domain:
                # check falsy to avoid trailing separators
                # adding empty domains
                domains.append(domain)
        return domains

    @validate('hosted_domain')
    def _cast_hosted_domain(self, proposal):
        """handle backward-compatibility with hosted_domain is a single domain as a string"""
        if isinstance(proposal.value, str):
            # pre-0.9 hosted_domain was a string
            # set it to a single item list
            # (or if it's empty, an empty list)
            if proposal.value == '':
                return []
            return [proposal.value.lower()]
        return [hd.lower() for hd in proposal.value]

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "google_group_whitelist": ("allowed_google_groups", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    google_group_whitelist = Dict(
        config=True,
        help="""
        .. deprecated:: 0.12

           Use :attr:`allowed_google_groups`.
        """,
    )

    def user_info_to_username(self, user_info):
        """
        Overrides the default implementation to conditionally also strip the
        user email's domain name from the username based on the hosted_domain
        configuration. The domain saved to user_info for use by authorization
        logic.
        """
        username = super().user_info_to_username(user_info)
        user_email = user_info["email"]
        user_domain = user_info["domain"] = user_email.split("@")[1].lower()

        # NOTE: This is not an authorization check, it just about username
        #       derivation. Decoupling hosted_domain from this is considered in
        #       https://github.com/jupyterhub/oauthenticator/issues/733.
        #
        # NOTE: This code is written with without knowing for sure if the user
        #       email's domain could be different from the domain in hd, so we
        #       assume it could be even though it seems like it can't be. If a
        #       Google organization/workspace manages users in a "primary
        #       domain" and a "secondary domain", users with respective email
        #       domain have their hd field set respectively.
        #
        if len(self.hosted_domain) == 1 and user_domain == self.hosted_domain[0]:
            # strip the domain in this situation
            username = username.split("@")[0]

        return username

    async def update_auth_model(self, auth_model):
        """
        Fetch and store `google_groups` in auth state if `allowed_google_groups`
        or `admin_google_groups` is configured.

        Sets admin status to True or False if `admin_google_groups` is
        configured and the user isn't part of `admin_users`. Note that leaving
        it at None makes users able to retain an admin status while setting it
        to False makes it be revoked.

        Strips the domain from the username if `hosted_domain` is configured
        with a single entry.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_email = user_info["email"]
        user_domain = user_info["domain"]

        user_groups = set()
        if self.allowed_google_groups or self.admin_google_groups:
            user_groups = self._fetch_user_groups(user_email, user_domain)
        # sets are not JSONable, cast to list for auth_state
        user_info["google_groups"] = list(user_groups)

        if auth_model["admin"]:
            # auth_model["admin"] being True means the user was in admin_users
            return auth_model

        if self.admin_google_groups:
            # admin status should in this case be True or False, not None
            admin_groups = self.admin_google_groups.get(user_domain, set())
            auth_model["admin"] = bool(user_groups & admin_groups)

        return auth_model

    def check_blocked_users(self, username, auth_model):
        """
        Overrides `Authenticator.check_blocked_users` to not only block users in
        `Authenticator.blocked_users`, but to also enforce
        `GoogleOAuthenticator.hosted_domain` if its configured.

        When hosted_domain is configured, users are required to be part of
        listed Google organizations/workspaces.

        Returns False if the user is blocked, otherwise True.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]

        # hd ref: https://developers.google.com/identity/openid-connect/openid-connect#id_token-hd
        hd = user_info.get("hd", "")

        if self.hosted_domain and hd not in self.hosted_domain:
            self.log.warning(f"Blocked {username} with 'hd={hd}' not in hosted_domain")
            return False

        return super().check_blocked_users(username, auth_model)

    async def check_allowed(self, username, auth_model):
        """
        Overrides the OAuthenticator.check_allowed to also allow users part of
        `allowed_google_groups`.
        """
        # A workaround for JupyterHub < 5.0 described in
        # https://github.com/jupyterhub/oauthenticator/issues/621
        if auth_model is None:
            return True

        # before considering allowing a username by being recognized in a list
        # of usernames or similar, we must ensure that the authenticated user
        # has a verified email and is part of hosted_domain if configured.
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_email = user_info["email"]
        user_domain = user_info["domain"]

        if not user_info["verified_email"]:
            message = f"Login with unverified email {user_email} is not allowed"
            self.log.warning(message)
            raise HTTPError(403, message)

        if await super().check_allowed(username, auth_model):
            return True

        if self.allowed_google_groups:
            user_groups = set(user_info["google_groups"])
            allowed_groups = self.allowed_google_groups.get(user_domain, set())
            if user_groups & allowed_groups:
                return True

        # users should be explicitly allowed via config, otherwise they aren't
        return False

    def _service_client_credentials(self, scopes, user_email_domain):
        """
        Return a configured service client credentials for the API.
        """
        try:
            from google.oauth2 import service_account
        except:
            raise ImportError(
                "Could not import google.oauth2's service_account,"
                "you may need to run 'pip install oauthenticator[googlegroups]' or not declare google groups"
            )

        gsuite_administrator_email = "{}@{}".format(
            self.gsuite_administrator[user_email_domain], user_email_domain
        )
        self.log.debug(f"scopes are {scopes}, user_email_domain is {user_email_domain}")
        credentials = service_account.Credentials.from_service_account_file(
            self.google_service_account_keys[user_email_domain], scopes=scopes
        )

        credentials = credentials.with_subject(gsuite_administrator_email)

        return credentials

    def _service_client(self, service_name, service_version, credentials, http=None):
        """
        Return a configured service client for the API.
        """
        try:
            from googleapiclient.discovery import build
        except:
            raise ImportError(
                "Could not import googleapiclient.discovery's build,"
                "you may need to run 'pip install oauthenticator[googlegroups]' or not declare google groups"
            )

        self.log.debug(
            f"service_name is {service_name}, service_version is {service_version}"
        )

        return build(
            serviceName=service_name,
            version=service_version,
            credentials=credentials,
            cache_discovery=False,
            http=http,
        )

    def _fetch_user_groups(self, user_email, user_email_domain, http=None):
        """
        Return a set with the google groups a given user is a member of
        """
        # FIXME: When this function is used and waiting for web request
        #        responses, JupyterHub gets blocked from doing other things.
        #        Ideally the web requests should be made using an async client
        #        that can be awaited while JupyterHub handles other things.
        #
        credentials = self._service_client_credentials(
            scopes=[f"{self.google_api_url}/auth/admin.directory.group.readonly"],
            user_email_domain=user_email_domain,
        )
        service = self._service_client(
            service_name='admin',
            service_version='directory_v1',
            credentials=credentials,
            http=http,
        )

        resp = service.groups().list(userKey=user_email).execute()
        user_groups = {
            g['email'].split('@')[0] for g in resp.get('groups', [{'email': None}])
        }
        self.log.debug(f"user_email {user_email} is a member of {user_groups}")
        return user_groups


class LocalGoogleOAuthenticator(LocalAuthenticator, GoogleOAuthenticator):
    """A version that mixes in local system user creation"""
