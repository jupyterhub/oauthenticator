"""
Custom Authenticator to use Google OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""
import os

from jupyterhub.auth import LocalAuthenticator
from tornado.auth import GoogleOAuth2Mixin
from tornado.web import HTTPError
from traitlets import Dict, List, Unicode, default, validate

from .oauth2 import OAuthenticator


def check_user_in_groups(member_groups, allowed_groups):
    # Check if user is a member of any group in the allowed groups
    if any(g in member_groups for g in allowed_groups):
        return True  # user _is_ in group
    else:
        return False


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
        List(Unicode()), help="Automatically allow members of selected groups"
    ).tag(config=True)

    admin_google_groups = Dict(
        List(Unicode()),
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
        user_email = auth_model["auth_state"][self.user_auth_state_key]['email']
        user_email_domain = user_email.split('@')[1]

        if not auth_model["auth_state"][self.user_auth_state_key]['verified_email']:
            self.log.warning(f"Google OAuth unverified email attempt: {user_email}")
            raise HTTPError(403, f"Google email {user_email} not verified")

        if self.hosted_domain:
            if user_email_domain not in self.hosted_domain:
                self.log.warning(
                    f"Google OAuth unauthorized domain attempt: {user_email}"
                )
                raise HTTPError(
                    403, f"Google account domain @{user_email_domain} not authorized."
                )

        if self.allowed_google_groups:
            google_groups = self._google_groups_for_user(user_email, user_email_domain)
            if not google_groups:
                return False

            auth_model['auth_state']['google_user']['google_groups'] = google_groups

            # Check if user is a member of any allowed groups.
            if user_email_domain in self.allowed_google_groups:
                return check_user_in_groups(
                    google_groups, self.allowed_google_groups[user_email_domain]
                )

        return True


    async def update_auth_model(self, auth_model, google_groups=None):
        username = auth_model["name"]
        admin_status = True if username in self.admin_users else None
        if admin_status:
            auth_model['admin'] = is_admin
        elif self.admin_google_groups:
            user_email_domain = auth_model['auth_state'][self.user_auth_state_key]['hd']

            # Check if user is a member of any admin groups.
            is_admin = check_user_in_groups(
                google_groups, self.admin_google_groups[user_email_domain]
            )
            auth_model['admin'] = is_admin

        return auth_model

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
        Return google groups a given user is a member of
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
        results = [
            g['email'].split('@')[0] for g in results.get('groups', [{'email': None}])
        ]
        self.log.debug(f"user_email {user_email} is a member of {results}")
        return results


class LocalGoogleOAuthenticator(LocalAuthenticator, GoogleOAuthenticator):
    """A version that mixes in local system user creation"""
