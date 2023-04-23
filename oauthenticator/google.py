"""
Custom Authenticator to use Google OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""
import os

from jupyterhub.auth import LocalAuthenticator
from tornado.auth import GoogleOAuth2Mixin
from tornado.web import HTTPError
from traitlets import Dict, List, Set, Unicode, default, validate

from .oauth2 import OAuthenticator


class GoogleOAuthenticator(OAuthenticator, GoogleOAuth2Mixin):
    _deprecated_oauth_aliases = {
        "google_group_whitelist": ("allowed_google_groups", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    user_auth_state_key = "google_user"

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://accounts.google.com/o/oauth2/v2/auth"

    @default("scope")
    def _scope_default(self):
        return ["openid", "email"]

    @default("username_claim")
    def _username_claim_default(self):
        return "email"

    google_api_url = Unicode("https://www.googleapis.com", config=True)

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
        help="Service account keys to use with each domain, see https://developers.google.com/admin-sdk/directory/v1/guides/delegation",
    ).tag(config=True)

    gsuite_administrator = Dict(
        Unicode(),
        help="Username of a G Suite Administrator for the service account to act as",
    ).tag(config=True)

    google_group_whitelist = Dict(
        help="Deprecated, use `GoogleOAuthenticator.allowed_google_groups`",
        config=True,
    )

    allowed_google_groups = Dict(
        Set(Unicode()), help="Automatically allow members of selected groups"
    ).tag(config=True)

    admin_google_groups = Dict(
        Set(Unicode()),
        help="Groups whose members should have Jupyterhub admin privileges",
    ).tag(config=True)

    user_info_url = Unicode(
        "https://www.googleapis.com/oauth2/v1/userinfo", config=True
    )

    hosted_domain = List(
        Unicode(),
        config=True,
        help="""List of domains used to restrict sign-in, e.g. mycollege.edu""",
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
            return [proposal.value]
        return proposal.value

    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Google'),
        config=True,
        help="""Google Apps hosted domain string, e.g. My College""",
    )

    async def user_is_authorized(self, auth_model):
        """
        Checks that the google user has a verified email and is part of
        `hosted_domain` if set.

        Authorizes users part of: `allowed_users`, `admin_users`,
        `allowed_google_groups`, or `admin_google_groups`.

        Note that this function also updates the auth_model with admin status
        and the user's google groups if either `allowed_google_groups` or
        `admin_google_groups` are configured.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_email = user_info["email"]
        user_domain = user_email.split("@")[1]

        if not user_info["verified_email"]:
            self.log.warning(f"Google OAuth unverified email attempt: {user_email}")
            raise HTTPError(403, f"Google email {user_email} not verified")

        if self.hosted_domain and user_domain not in self.hosted_domain:
            self.log.warning(f"Google OAuth unauthorized domain attempt: {user_email}")
            raise HTTPError(403, f"Google account domain @{user_domain} not authorized")

        username = auth_model["name"]
        if username in self.admin_users:
            auth_model["admin"] = True

        # always set google_groups if associated config is provided, and to a
        # list rather than set, for backward compatibility
        if self.allowed_google_groups or self.admin_google_groups:
            # FIXME: _google_groups_for_user is a non-async function that blocks
            #        JupyterHub, and it also doesn't have any cache. If this is
            #        solved, we could also let this function not modify the
            #        auth_model.
            #
            user_groups = self._google_groups_for_user(user_email, user_domain)
            user_info["google_groups"] = list(user_groups)

            allowed_groups = self.allowed_google_groups.get(user_domain, set())
            admin_groups = self.admin_google_groups.get(user_domain, set())

            # only set admin if not already set
            if not auth_model["admin"]:
                auth_model["admin"] = any(user_groups & admin_groups)

            if any(user_groups & (allowed_groups | admin_groups)):
                return True

        return username in (self.allowed_users | self.admin_users)

    def _service_client_credentials(self, scopes, user_email_domain):
        """
        Return a configured service client credentials for the API.
        """
        try:
            from google.oauth2 import service_account
        except:
            raise ImportError(
                "Could not import google.oauth2's service_account,"
                "you may need to run pip install oauthenticator[googlegroups] or not declare google groups"
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
                "you may need to run pip install oauthenticator[googlegroups] or not declare google groups"
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

    def _google_groups_for_user(self, user_email, user_email_domain, http=None):
        """
        Return a set with the google groups a given user is a member of
        """
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

        results = service.groups().list(userKey=user_email).execute()
        results = {
            g['email'].split('@')[0] for g in results.get('groups', [{'email': None}])
        }
        self.log.debug(f"user_email {user_email} is a member of {results}")
        return results


class LocalGoogleOAuthenticator(LocalAuthenticator, GoogleOAuthenticator):
    """A version that mixes in local system user creation"""
