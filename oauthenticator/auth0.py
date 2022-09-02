"""
Custom Authenticator to use Auth0 OAuth with JupyterHub

Derived using the Github and Google OAuthenticator implementations as examples.

The following environment variables may be used for configuration:

* AUTH0_DOMAIN - The domain for your Auth0 account
* AUTH0_SUBDOMAIN - Alternative to AUTH0_DOMAIN if your domain ends with .auth0.com
* OAUTH_CLIENT_ID - Your client id
* OAUTH_CLIENT_SECRET - Your client secret
* OAUTH_CALLBACK_URL - Your callback handler URL

You must provide either AUTH0_DOMAIN or AUTH0_SUBDOMAIN. If both are provided,
AUTH0_DOMAIN will take precedence.

Additionally, if you are concerned about your secrets being exposed by
an env dump(I know I am!) you can set the client_secret, client_id and
oauth_callback_url directly on the config for Auth0OAuthenticator.

One instance of this could be adding the following to your jupyterhub_config.py::

  c.Auth0OAuthenticator.auth0_domain = 'auth.example.com'
  c.Auth0OAuthenticator.client_id = 'YOUR_CLIENT_ID'
  c.Auth0OAuthenticator.client_secret = 'YOUR_CLIENT_SECRET'
  c.Auth0OAuthenticator.oauth_callback_url = 'YOUR_CALLBACK_URL'
  c.Auth0OAuthenticator.scope = ['openid','profile','email']

If you are using the environment variable config, all you should need to
do is define them in the environment then add the following line to 
jupyterhub_config.py :

  c.JupyterHub.authenticator_class = 'oauthenticator.auth0.Auth0OAuthenticator'

"""
import json
import os

from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPRequest
from traitlets import Unicode, default

from .oauth2 import OAuthenticator


class Auth0OAuthenticator(OAuthenticator):

    login_service = "Auth0"

    auth0_subdomain = Unicode(config=True)
    auth0_domain = Unicode(config=True)

    @default("auth0_subdomain")
    def _auth0_subdomain_default(self):
        # This is allowed to be empty unless auth0_domain is not supplied either
        return os.getenv("AUTH0_SUBDOMAIN", "")

    @default("auth0_domain")
    def _auth0_domain_default(self):
        domain = os.getenv("AUTH0_DOMAIN", "")
        if domain:
            return domain
        if self.auth0_subdomain:
            return '%s.auth0.com' % self.auth0_subdomain
        raise ValueError(
            "Please specify $AUTH0_DOMAIN env, $AUTH0_SUBDOMAIN env, %s.auth0_domain config, or %s.auth0_subdomain config"
            % (self.__class__.__name__, self.__class__.__name__)
        )

    username_key = Unicode(
        os.environ.get("OAUTH2_USERNAME_KEY", "email"),
        config=True,
        help="Userdata username key from returned json with user data login information",
    )

    @default("logout_redirect_url")
    def _logout_redirect_url_default(self):
        return 'https://%s/v2/logout' % self.auth0_domain

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://%s/authorize" % self.auth0_domain

    @default("token_url")
    def _token_url_default(self):
        return "https://%s/oauth/token" % self.auth0_domain

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.get_callback_url(handler),
        }
        url = self.token_url

        req = HTTPRequest(
            url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(params),
        )

        resp_json = await self.fetch(req)

        access_token = resp_json['access_token']

        refresh_token = resp_json.get('refresh_token')
        id_token = resp_json.get('id_token')

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token),
        }
        req = HTTPRequest(
            "https://%s/userinfo" % self.auth0_domain,
            method="GET",
            headers=headers,
        )
        resp_json = await self.fetch(req)

        name = resp_json.get(self.username_key)
        if not name:
            self.log.error(
                "Auth0 user contains no key %s: %s", self.username_key, resp_json
            )
            return

        return {
            'name': name,
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'id_token': id_token,
                'auth0_user': resp_json,
            },
        }


class LocalAuth0OAuthenticator(LocalAuthenticator, Auth0OAuthenticator):

    """A version that mixes in local system user creation"""

    pass
