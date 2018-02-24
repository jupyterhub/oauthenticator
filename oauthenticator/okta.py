"""
Custom Authenticator to use Okta OAuth with JupyterHub

Derived using the Auth0 OAuthenticator implementations as examples.

The following environment variables may be used for configuration:

    OKTA_DOMAIN - The domain for your Okta account; should end with okta.com or oktapreview.com
    OAUTH_CLIENT_ID - Your client id
    OAUTH_CLIENT_SECRET - Your client secret
    OAUTH_CALLBACK_URL - Your callback handler URL

Additionally, if you are concerned about your secrets being exposed by
an env dump(I know I am!) you can set the client_secret, client_id and
oauth_callback_url directly on the config for OktaOAuthenticator.

One instance of this could be adding the following to your jupyterhub_config.py :

  c.OktaOAuthenticator.client_id = 'YOUR_CLIENT_ID'
  c.OktaOAuthenticator.client_secret = 'YOUR_CLIENT_SECRET'
  c.OktaOAuthenticator.oauth_callback_url = 'YOUR_CALLBACK_URL'

If you are using the environment variable config, all you should need to
do is define them in the environment then add the following line to 
jupyterhub_config.py :

  c.JupyterHub.authenticator_class = 'oktaoauthenticator.OktaOAuthenticator'

"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.httputil import url_concat

# from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator

OKTA_DOMAIN = os.getenv('OKTA_DOMAIN')
if not OKTA_DOMAIN:
    raise Exception('Environment variable OKTA_DOMAIN must be set')

OKTA_AUTHORIZE_URL = "https://%s/oauth2/v1/authorize" % OKTA_DOMAIN
OKTA_ACCESS_TOKEN_URL = "https://%s/oauth2/v1/token" % OKTA_DOMAIN
OKTA_USERINFO_URL = "https://%s/oauth2/v1/userinfo" % OKTA_DOMAIN

class OktaMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = OKTA_AUTHORIZE_URL
    _OAUTH_ACCESS_TOKEN_URL = OKTA_ACCESS_TOKEN_URL


class OktaLoginHandler(OAuthLoginHandler, OktaMixin):
    pass

class OktaOAuthenticator(OAuthenticator):

    login_service = "Okta"
    
    login_handler = OktaLoginHandler

    def _scope_default(self):
        scopes_string = os.getenv('OAUTH_SCOPES', 'openid email groups profile')
        return scopes_string.split(' ')

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        
        http_client = AsyncHTTPClient()

        params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'scope': ' '.join(self.scope),
            'redirect_uri': self.get_callback_url(handler)
        }

        # self.log.debug("Okta token request scope: {}".format(' '.join(self.scope)))
        url = url_concat(OKTA_ACCESS_TOKEN_URL, params)
        self.log.debug("Okta token request URL: {}".format(url))
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='',
                          )
        
        resp = yield http_client.fetch(req)
        # self.log.debug("Okta token response: {}".format(resp))
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.debug("Okta token response JSON: {}".format(resp_json))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest(OKTA_USERINFO_URL,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        # self.log.debug("Okta userinfo response: {}".format(resp))
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.debug("Okta userinfo response JSON: {}".format(resp_json))
        # TODO: verify the returned JWT, ex: https://github.com/mogthesprog/jwtauthenticator/blob/master/jwtauthenticator/jwtauthenticator.py
        return {
            'name': resp_json["email"],
            'auth_state': {
                'access_token': access_token,
                'okta_user': resp_json,
            }
        }
