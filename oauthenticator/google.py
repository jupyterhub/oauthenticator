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
        Restrict sign-in to a list of email domain names, such as
        `["mycollege.edu"]`.

        Note that users with email domains in this list must still be allowed
        via another config, such as `allow_all`, `allowed_users`, or
        `allowed_google_groups`.
        """,
    )

    @default('hosted_domain')
    def _hosted_domain_from_env(self):
        domains = []
        for domain in os.environ.get('HOSTED_DOMAIN', '').split(';'):
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

    async def update_auth_model(self, auth_model):
        """
        Fetch and store `google_groups` in auth state if `allowed_google_groups`
        or `admin_google_groups` is configured.

        Sets admin status to True or False if `admin_google_groups` is
        configured and the user isn't part of `admin_users`. Note that leaving
        it at None makes users able to retain an admin status while setting it
        to False makes it be revoked.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_email = user_info["email"]
        user_domain = user_info["domain"] = user_email.split("@")[1].lower()

        user_groups = set()
        if self.allowed_google_groups or self.admin_google_groups:
            user_groups = user_info["google_groups"] = self._fetch_user_groups(
                user_email, user_domain
            )
        user_info["google_groups"] = user_groups

        if auth_model["admin"]:
            # auth_model["admin"] being True means the user was in admin_users
            return auth_model

        if self.admin_google_groups:
            # admin status should in this case be True or False, not None
            admin_groups = self.admin_google_groups.get(user_domain, set())
            auth_model["admin"] = any(user_groups & admin_groups)

        return auth_model

    async def check_allowed(self, username, auth_model):
        """
        Overrides the OAuthenticator.check_allowed to also allow users part of
        `allowed_google_groups`.
        """
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

        # NOTE: If hosted_domain is configured as ["a.com", "b.com"], and
        #       allowed_google_groups is declared as {"a.com": {"a-group"}}, a
        #       "b.com" user won't be authorized unless allowed in another way.
        #
        #       This means that its not possible to allow all users of a given
        #       domain if one wants to restrict another.
        #
        if self.hosted_domain:
            if user_domain not in self.hosted_domain:
                message = f"Login with domain @{user_domain} is not allowed"
                self.log.warning(message)
                raise HTTPError(403, message)

        if await super().check_allowed(username, auth_model):
            return True

        if self.allowed_google_groups:
            user_groups = user_info["google_groups"]
            allowed_groups = self.allowed_google_groups.get(user_domain, set())
            if any(user_groups & allowed_groups):
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
