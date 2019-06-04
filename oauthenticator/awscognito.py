"""
Custom Authenticator to use AWSCognito with JupyterHub

Derived using the Globus and Generic OAuthenticator implementations as examples.

The following environment variables may be used for configuration:

    AWSCOGNITO_DOMAIN - Your AWSCognito domain, either AWS provided or custom
    AWSCOGNITO_USERNAME_KEY - Your username key, you can use preferred_username, username, email
    OAUTH_CLIENT_ID - Your client id
    OAUTH_CLIENT_SECRET - Your client secret
    OAUTH_CALLBACK_URL - Your callback handler URL
    OAUTH_LOGOUT_REDIRECT_URL - Your logout redirect URL

Additionally, if you are concerned about your secrets being exposed by
an env dump(I know I am!) you can set the client_secret, client_id and
oauth_callback_url directly on the config for Auth0OAuthenticator.

One instance of this could be adding the following to your jupyterhub_config.py :

  c.AWSCognitoAuthenticator.client_id = 'YOUR_CLIENT_ID'
  c.AWSCognitoAuthenticator.client_secret = 'YOUR_CLIENT_SECRET'
  c.AWSCognitoAuthenticator.oauth_callback_url = 'YOUR_CALLBACK_URL'
  c.AWSCognitoAuthenticator.username_key = 'YOUR_USERNAME_KEY'
  c.AWSCognitoAuthenticator.oauth_logout_redirect_url = 'YOUR_LOGOUT_REDIRECT_URL'

If you are using the environment variable config, all you should need to
do is define them in the environment then add the following line to
jupyterhub_config.py :

  c.JupyterHub.authenticator_class = 'oauthenticator.awscognito.AWSCognitoAuthenticator'

"""

import json
import os
import base64
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen

from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.httputil import url_concat

from jupyterhub.handlers import LogoutHandler
from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

AWSCOGNITO_DOMAIN = os.getenv('AWSCOGNITO_DOMAIN')


class AWSCognitoMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/oauth2/authorize" % AWSCOGNITO_DOMAIN
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/oauth2/token" % AWSCOGNITO_DOMAIN

class AWSCognitoLoginHandler(OAuthLoginHandler, AWSCognitoMixin):
    pass


class AWSCognitoLogoutHandler(LogoutHandler):
    """
    Handle custom logout URLs and token revocation. If a custom logout url
    is specified, the 'logout' button will log the user out of that identity
    provider in addition to clearing the session with Jupyterhub, otherwise
    only the Jupyterhub session is cleared.
    """
    async def render_logout_page(self):
        params = dict(
            client_id=self.authenticator.client_id,
            logout_uri=self.authenticator.oauth_logout_redirect_url
        )
        url = url_concat(self.authenticator.oidc_logout_url, params)
        self.log.debug("Redirecting to AWSCognito logout: {0}".format(url))
        self.redirect(url, permanent=False)


class AWSCognitoAuthenticator(OAuthenticator):

    login_service = 'AWSCognito'
    login_handler = AWSCognitoLoginHandler

    oidc_userdata_url = "https://%s/oauth2/userInfo" % AWSCOGNITO_DOMAIN
    oidc_token_url = "https://%s/oauth2/token" % AWSCOGNITO_DOMAIN
    oidc_logout_url = "https://%s/logout" % AWSCOGNITO_DOMAIN

    username_key = Unicode(
        os.environ.get('AWSCOGNITO_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )

    oauth_logout_redirect_url = Unicode(
        os.environ.get('OAUTH_LOGOUT_REDIRECT_URL', ''),
        config=True,
        help="Logout redirect URL to be shown after IdP logout"
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )

        if self.oidc_token_url:
            url = self.oidc_token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )
        headers.update({"Authorization": "Basic {}".format(b64key.decode("utf8"))})

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=True,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        token_type = resp_json['token_type']

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        if self.oidc_userdata_url:
            url = self.oidc_userdata_url
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        req = HTTPRequest(url,
                          method='GET',
                          headers=headers,
                          validate_cert=True,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if not resp_json.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
            return

        return {
            'name': resp_json.get(self.username_key),
            'auth_state': {
                'access_token': access_token,
                'awscognito_user': resp_json,
            }
        }

    def get_handlers(self, app):
        return super().get_handlers(app) + [(r'/logout', AWSCognitoLogoutHandler)]


class LocalAWSCognitoAuthenticator(LocalAuthenticator, AWSCognitoAuthenticator):

    """A version that mixes in local system user creation"""
    pass
