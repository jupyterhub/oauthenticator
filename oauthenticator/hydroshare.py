"""
Custom Authenticator to use HydroShare OAuth with JupyterHub

"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import LocalAuthenticator, Authenticator
from jupyterhub.utils import url_path_join

from traitlets import Unicode, Dict

from .oauth2 import OAuthLoginHandler, OAuthenticator, OAuthCallbackHandler

from urllib.parse import unquote
from pwd import getpwnam
import grp
import shutil
import requests

# hold on the the next_url for redirecting after authentication
next_url = None
    
class HydroShareMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = 'https://www.hydroshare.org/o/authorize'
    _OAUTH_ACCESS_TOKEN_URL = 'https://www.hydroshare.org/o/token'


class HydroShareLoginHandler(OAuthLoginHandler, HydroShareMixin):

    def get(self):
        # store the uri that was recieved
        self.url = self.request.uri
        print('LOGIN URL RECIEVED: ' + self.url)
        guess_uri = '{proto}://{host}{path}'.format(
            proto=self.request.protocol,
            host=self.request.host,
            path=url_path_join(
                self.hub.server.base_url,
                'oauth_callback'
            )
        )
        
        redirect_uri = self.authenticator.oauth_callback_url or guess_uri
        self.log.info('oauth redirect: %r', redirect_uri)
        
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=self.scope,
            response_type='code',
            callback=self.setNextUrl)

    def setNextUrl(self):
        # clean the next uri and generate an absolute path
        clean_url = unquote(self.url.split('=')[-1]) 
        redirect_url = '{proto}://{host}{path}'.format(
            proto=self.request.protocol,
            host=self.request.host,
            path=clean_url
        )

        self.log.info('NEXT URL: ' + redirect_url)

        # save this url path so that it can be accessed in the CallbackHandler
        global next_url
        next_url = redirect_url

class HydroShareCallbackHandler(OAuthCallbackHandler, HydroShareMixin):
#    """Basic handler for OAuth callback. Calls authenticator to verify username."""
    @gen.coroutine
    def get(self):
        self.log.info('Inside HydroShareCallbackHandler')
        username = yield self.authenticator.get_authenticated_user(self, None)

        if username:

            self.log.info('base url: ' +self.request.uri)
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            print('CALLBACKHANDLER REDIRECTING TO: '+next_url) 

            # redirect the user to the next uri, or the server homepage
            redirect_file = os.path.join(os.environ['HYDROSHARE_REDIRECT_COOKIE_PATH'], '.redirect_%s'%username)
            welcome_page = '%s/user/%s/tree/notebooks/Welcome.ipynb' % (self.hub.server.base_url, username)
            if os.path.exists(redirect_file):
                print('FOUND REDIRECT FILE AT: %s' % redirect_file)
                with open(redirect_file,'r') as f:
                    u = f.read().strip()
                    os.remove(redirect_file)
                try:
                    response = requests.head(u)
                    response.raise_for_status()
                except Exception as e:
                    print('EXCEPTION: A 4xx or 5xx code was recieved. Redirecting to: %s' % welcome_page)
                    self.redirect(welcome_page)
                else:
                    self.redirect(u)
            else:
                self.redirect(welcome_page)
        else:
            raise web.HTTPError(403)

class HydroShareOAuthenticator(OAuthenticator):

    login_service = "HydroShare"

    client_id_env = 'HYDROSHARE_CLIENT_ID'
    client_secret_env = 'HYDROSHARE_CLIENT_SECRET'
    login_handler = HydroShareLoginHandler
    callback_handler = HydroShareCallbackHandler

    username_map = Dict(config=True, default_value={},
                        help="""Optional dict to remap github usernames to nix usernames.
        """)

    @gen.coroutine
    def authenticate(self, handler, data):
        print('request uri: ' + handler.request.uri)
        code = handler.get_argument("code", False)
        self.log.info('code: ' + code)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")

        http_client = AsyncHTTPClient()

        # POST request parameters for HydroShare  
        params = dict(
            grant_type='authorization_code',
            code=code,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.oauth_callback_url,
        )

        url = url_concat(
                        'https://www.hydroshare.org/o/token/',
                         params)
        self.log.info(url)

        self.log.info('url: '+str(url))

        req = HTTPRequest(url,method="POST",body='', headers={"Accept": "application/json"}, validate_cert=False,)

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        self.log.info('RESPONSE_JSON: '+str(resp_json))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("https://hydroshare.org/hsapi/userInfo",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        self.log.info('user: '+str(resp_json))
        
        # get the username variable from the response
        hs_username = resp_json["username"]
        
        # remap hydroshare username to system username
        nix_username = self.username_map.get(hs_username, hs_username)
        
        #check system username against whitelist
        use_whitelist = int(os.getenv('HYDROSHARE_USE_WHITELIST', '1'))
        if use_whitelist:
            if self.whitelist and nix_username not in self.whitelist:
                self.log.error('Username not in whitelist: %s' % nix_username)
                nix_username = None
        return nix_username



