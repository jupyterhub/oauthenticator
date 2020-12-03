"""
Custom Authenticator to use Google OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""

import os
import json
import urllib.parse

from tornado import gen
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.auth import GoogleOAuth2Mixin
from tornado.web import HTTPError

from traitlets import Dict, Unicode, List, default, validate, observe

from jupyterhub.crypto import decrypt, EncryptionUnavailable, InvalidToken
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator

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

    google_api_url = Unicode("https://www.googleapis.com", config=True)

    @default('google_api_url')
    def _google_api_url(self):
        """get default google apis url from env"""
        google_api_url = os.getenv('GOOGLE_API_URL')

        # default to googleapis.com
        if not google_api_url:
            google_api_url = 'https://www.googleapis.com'

        return google_api_url

    @default('scope')
    def _scope_default(self):
        return ['openid', 'email']

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://accounts.google.com/o/oauth2/v2/auth"

    @default("token_url")
    def _token_url_default(self):
        return "%s/oauth2/v4/token" % (self.google_api_url)

    google_service_account_keys = Dict(
        Unicode(),
        help="Service account keys to use with each domain, see https://developers.google.com/admin-sdk/directory/v1/guides/delegation"
    ).tag(config=True)

    gsuite_administrator = Dict(
        Unicode(),
        help="Username of a G Suite Administrator for the service account to act as"
    ).tag(config=True)

    google_group_whitelist = Dict(help="Deprecated, use `GoogleOAuthenticator.allowed_google_groups`", config=True,)

    allowed_google_groups = Dict(
        List(Unicode()),
        help="Automatically allow members of selected groups"
    ).tag(config=True)

    admin_google_groups = Dict(
        List(Unicode()),
        help="Groups whose members should have Jupyterhub admin privileges"
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

    async def authenticate(self, handler, data=None, google_groups=None):
        code = handler.get_argument("code")
        body = urllib.parse.urlencode(
            dict(
                code=code,
                redirect_uri=self.get_callback_url(handler),
                client_id=self.client_id,
                client_secret=self.client_secret,
                grant_type="authorization_code",
            )
        )

        http_client = AsyncHTTPClient()

        response = await http_client.fetch(
            self.token_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )

        user = json.loads(response.body.decode("utf-8", "replace"))
        access_token = str(user['access_token'])
        refresh_token = user.get('refresh_token', None)

        response = await http_client.fetch(
            self.user_info_url + '?access_token=' + access_token
        )

        if not response:
            handler.clear_all_cookies()
            raise HTTPError(500, 'Google authentication failed')

        bodyjs = json.loads(response.body.decode())
        user_email = username = bodyjs['email']
        user_email_domain = user_email.split('@')[1]

        if not bodyjs['verified_email']:
            self.log.warning("Google OAuth unverified email attempt: %s", user_email)
            raise HTTPError(403, "Google email {} not verified".format(user_email))

        if self.hosted_domain:
            if user_email_domain not in self.hosted_domain:
                self.log.warning(
                    "Google OAuth unauthorized domain attempt: %s", user_email
                )
                raise HTTPError(
                    403,
                    "Google account domain @{} not authorized.".format(
                        user_email_domain
                    ),
                )
            if len(self.hosted_domain) == 1:
                # unambiguous domain, use only base name
                username = user_email.split('@')[0]

        if refresh_token is None:
            self.log.debug("Refresh token was empty, will try to pull refresh_token from previous auth_state")
            user = handler.find_user(username)

            if user and user.encrypted_auth_state:
                self.log.debug("encrypted_auth_state was found, will try to decrypt and pull refresh_token from it")
                try:
                    encrypted = user.encrypted_auth_state
                    auth_state = await decrypt(encrypted)
                    refresh_token = auth_state.get('refresh_token')
                except (ValueError, InvalidToken, EncryptionUnavailable) as e:
                    self.log.warning(
                        "Failed to retrieve encrypted auth_state for %s because %s",
                        username,
                        e,
                    )

        user_info = {
            'name': username,
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'google_user': bodyjs
            }
        }

        if self.admin_google_groups or self.allowed_google_groups:
            user_info = await self._add_google_groups_info(user_info, google_groups)

        return user_info

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

        gsuite_administrator_email = "{}@{}".format(self.gsuite_administrator[user_email_domain], user_email_domain)
        self.log.debug("scopes are %s, user_email_domain is %s", scopes, user_email_domain)
        credentials = service_account.Credentials.from_service_account_file(
            self.google_service_account_keys[user_email_domain],
            scopes=scopes
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

        self.log.debug("service_name is %s, service_version is %s", service_name, service_version)

        return build(
            serviceName=service_name,
            version=service_version,
            credentials=credentials,
            cache_discovery=False,
            http=http)

    async def _google_groups_for_user(self, user_email, credentials, http=None):
        """
        Return google groups a given user is a member of
        """
        service = self._service_client(
            service_name='admin',
            service_version='directory_v1',
            credentials=credentials,
            http=http)

        results = service.groups().list(userKey=user_email).execute()
        results = [ g['email'].split('@')[0] for g in results.get('groups', [{'email': None}]) ]
        self.log.debug("user_email %s is a member of %s", user_email, results)
        return results

    async def _add_google_groups_info(self, user_info, google_groups=None):
        user_email_domain=user_info['auth_state']['google_user']['hd']
        user_email=user_info['auth_state']['google_user']['email']
        if google_groups is None:
            credentials = self._service_client_credentials(
                    scopes=['%s/auth/admin.directory.group.readonly' % (self.google_api_url)],
                    user_email_domain=user_email_domain)
            google_groups = await self._google_groups_for_user(
                    user_email=user_email,
                    credentials=credentials)
        user_info['auth_state']['google_user']['google_groups'] = google_groups

        # Check if user is a member of any admin groups.
        if self.admin_google_groups:
            is_admin = check_user_in_groups(google_groups, self.admin_google_groups[user_email_domain])
        # Check if user is a member of any allowed groups.
        user_in_group = check_user_in_groups(google_groups, self.allowed_google_groups[user_email_domain])

        if self.admin_google_groups and (is_admin or user_in_group):
            user_info['admin'] = is_admin
            return user_info
        elif user_in_group:
            return user_info
        else:
            return None


class LocalGoogleOAuthenticator(LocalAuthenticator, GoogleOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
