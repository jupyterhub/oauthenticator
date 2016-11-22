"""
Custom Authenticator to use Auth0 OAuth with JupyterHub

Derived using the Github and Google OAuthenticator implementations as examples.

The following environment variables may be used for configuration:

    AUTH0_SUBDOMAIN - The subdomain for your Auth0 account
    OAUTH_CLIENT_ID - Your client id
    OAUTH_CLIENT_SECRET - Your client secret
    OAUTH_CALLBACK_URI - Your callback handler URI

Additionally, if you are concerned about your secrets being exposed by
an env dump(I know I am!) you can create a function that returns them in 
a dict and attach them to the config object for Auth0OAuthenticator.

One instance of this could be adding the following to your jupyterhub_config.py :

  def oauth_variable_config():
    return {
      'OAUTH_CLIENT_ID':'YOUR_CLIENT_ID',
      'OAUTH_CLIENT_SECRET':'YOUR_CLIENT_SECRET',
      'OAUTH_CALLBACK_URI':'YOUR_CALLBACK_URI'
    }
  c.Auth0OAuthenticator.oauth_variable_config = oauth_variable_config

If you are using the environment variable config, all you should need to
do is define them in the environment then add the following line to 
jupyterhub_config.py :

  c.JupyterHub.authenticator_class = 'oauthenticator.auth0.Auth0OAuthenticator'

"""


import json
import os

import logging

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Any, default

from .oauth2 import OAuthLoginHandler, OAuthenticator

AUTH0_SUBDOMAIN = os.getenv('AUTH0_SUBDOMAIN')

class Auth0Mixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s.auth0.com/authorize" % AUTH0_SUBDOMAIN
    _OAUTH_ACCESS_TOKEN_URL = "https://%s.auth0.com/oauth/token" % AUTH0_SUBDOMAIN


class Auth0LoginHandler(OAuthLoginHandler, Auth0Mixin):
    def get(self):
        redirect_uri = self.authenticator.oauth_callback_url
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.oauth_client_id,
            scope=self.scope,
            response_type='code')

class Auth0OAuthenticator(OAuthenticator):

    oauth_variable_config = Any(
        help="""Any callable that returns a dictionary of oauth variables by the following names:
        OAUTH_CLIENT_ID
        OAUTH_CLIENT_SECRET
        OAUTH_CALLBACK_URI
        """
    ).tag(config=True)

    def oauth_environment_variable_config(self):
        return {
            'OAUTH_CLIENT_ID' : os.getenv('OAUTH_CLIENT_ID',''),
            'OAUTH_CLIENT_SECRET' : os.getenv('OAUTH_CLIENT_SECRET',''),
            'OAUTH_CALLBACK_URI' : os.getenv('OAUTH_CALLBACK_URI','')
        }

    @default('oauth_variable_config')
    def _get_default_oauth_variable_config(self):
        return self.oauth_environment_variable_config

    def __init__(self, *args, **kwargs):
        super(Auth0OAuthenticator, self).__init__(*args, **kwargs)
        oauth_config = self.oauth_variable_config()
        self.oauth_client_id = oauth_config['OAUTH_CLIENT_ID']
        self.oauth_client_secret = oauth_config['OAUTH_CLIENT_SECRET']
        self.oauth_callback_uri = oauth_config['OAUTH_CALLBACK_URI']
        self.oauth_callback_url = self.oauth_callback_uri

    login_service = "Auth0"
    
    login_handler = Auth0LoginHandler
    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = {
            'grant_type': 'authorization_code',
            'client_id': self.oauth_client_id,
            'client_secret': self.oauth_client_secret,
            'code':code,
            'redirect_uri': self.oauth_callback_uri
        }
        url = "https://%s.auth0.com/oauth/token" % AUTH0_SUBDOMAIN

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Content-Type": "application/json"},
                          body=json.dumps(params)
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("https://%s.auth0.com/userinfo" % AUTH0_SUBDOMAIN,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["email"]


class LocalAuth0OAuthenticator(LocalAuthenticator, Auth0OAuthenticator):

    """A version that mixes in local system user creation"""
    pass

