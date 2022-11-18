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
import os

from jupyterhub.auth import LocalAuthenticator
from traitlets import Unicode, default

from .oauth2 import OAuthenticator


class Auth0OAuthenticator(OAuthenticator):

    _deprecated_oauth_aliases = {
        "username_key": ("username_claim", "16.0.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

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
        config=True,
        help="Deprecated, use `Auth0OAuthenticator.username_claim`",
    )

    @default("user_auth_state_key")
    def _user_auth_state_key_default(self):
        return "auth0_user"

    @default("username_claim")
    def _username_claim_default(self):
        return "email"

    @default("logout_redirect_url")
    def _logout_redirect_url_default(self):
        return 'https://%s/v2/logout' % self.auth0_domain

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://%s/authorize" % self.auth0_domain

    @default("token_url")
    def _token_url_default(self):
        return "https://%s/oauth/token" % self.auth0_domain

    @default("userdata_url")
    def _userdata_url_default(self):
        return "https://%s/userinfo" % self.auth0_domain


class LocalAuth0OAuthenticator(LocalAuthenticator, Auth0OAuthenticator):

    """A version that mixes in local system user creation"""

    pass
