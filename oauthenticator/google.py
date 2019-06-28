"""
Custom Authenticator to use Google OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""

import os
import json

from tornado import gen
from tornado.auth import GoogleOAuth2Mixin
from tornado.web import HTTPError

from traitlets import Unicode, List, default, validate

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator


class GoogleLoginHandler(OAuthLoginHandler, GoogleOAuth2Mixin):
    '''An OAuthLoginHandler that provides scope to GoogleOAuth2Mixin's
       authorize_redirect.'''
    @property
    def scope(self):
        return self.authenticator.scope


class GoogleOAuthHandler(OAuthCallbackHandler, GoogleOAuth2Mixin):
    pass


class GoogleOAuthenticator(OAuthenticator, GoogleOAuth2Mixin):

    login_handler = GoogleLoginHandler
    callback_handler = GoogleOAuthHandler

    @default('scope')
    def _scope_default(self):
        return ['openid', 'email']

    hosted_domain = List(
        Unicode(),
        config=True,
        help="""List of domains used to restrict sign-in, e.g. mycollege.edu"""
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
        help="""Google Apps hosted domain string, e.g. My College"""
    )

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        handler.settings['google_oauth'] = {
            'key': self.client_id,
            'secret': self.client_secret,
            'scope': self.scope,
        }
        user = await handler.get_authenticated_user(
            redirect_uri=self.get_callback_url(handler),
            code=code)
        access_token = str(user['access_token'])

        http_client = handler.get_auth_http_client()

        response = await http_client.fetch(
            self._OAUTH_USERINFO_URL + '?access_token=' + access_token
        )

        if not response:
            handler.clear_all_cookies()
            raise HTTPError(500, 'Google authentication failed')

        bodyjs = json.loads(response.body.decode())
        user_email = username = bodyjs['email']
        user_email_domain = user_email.split('@')[1]

        if not bodyjs['verified_email']:
            self.log.warning("Google OAuth unverified email attempt: %s", user_email)
            raise HTTPError(403,
                "Google email {} not verified".format(user_email)
            )

        if self.hosted_domain:
            if (
                user_email_domain not in self.hosted_domain or
                bodyjs['hd'] not in self.hosted_domain
            ):
                self.log.warning("Google OAuth unauthorized domain attempt: %s", user_email)
                raise HTTPError(403,
                    "Google account domain @{} not authorized.".format(user_email_domain)
                )
            if len(self.hosted_domain) == 1:
                # unambiguous domain, use only base name
                username = user_email.split('@')[0]

        return {
            'name': username,
            'auth_state': {
                'access_token': access_token,
                'google_user': bodyjs,
            }
        }

class LocalGoogleOAuthenticator(LocalAuthenticator, GoogleOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
