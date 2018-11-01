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
import pickle

# hold on the the next_url for redirecting after authentication
next_url = None
    
class HydroShareMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = 'https://www.hydroshare.org/o/authorize'
    _OAUTH_ACCESS_TOKEN_URL = 'https://www.hydroshare.org/o/token'


class HydroShareLoginHandler(OAuthLoginHandler, HydroShareMixin):

    def get(self):
        # store the uri that was recieved
        self.url = self.request.uri
        guess_uri = '{proto}://{host}{path}'.format(
            proto=self.request.protocol,
            host=self.request.host,
            path=url_path_join(
                self.hub.server.base_url,
                'oauth_callback'
            )
        )
        redirect_uri = self.authenticator.oauth_callback_url or guess_uri
        self.log.debug('HydroShareLoginHandler, oauth redirect: %r', redirect_uri)
        
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=[],
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

        self.log.debug('HydroShareLoginHandler, next url: ' + redirect_url)

        # save this url path so that it can be accessed in the CallbackHandler
        global next_url
        next_url = redirect_url

class HydroShareCallbackHandler(OAuthCallbackHandler, HydroShareMixin):
#    """Basic handler for OAuth callback. Calls authenticator to verify username."""
    @gen.coroutine
    def get(self):
        user_data = yield self.authenticator.get_authenticated_user(self, None)

        if user_data:
            username = user_data['name']
            self.log.info('HydroShareCallbackHandler, base url: ' +self.request.uri)

            # get or generate jupyter user object. this calls user_from_username in jupyterhub/handlers/base.py
            user = self.user_from_username(username)
            self.set_login_cookie(user)

            self.log.debug('HydroShareCallbackHandler, redirect url: '+next_url) 

            # redirect the user to the next uri, or the server homepage
            redirect_file = os.path.join(os.environ['HYDROSHARE_REDIRECT_COOKIE_PATH'], '.redirect_%s'%username)
            welcome_page = '%s/user/%s/tree/notebooks/Welcome.ipynb' % (self.hub.server.base_url, username)
            if os.path.exists(redirect_file):
                self.log.debug('HydroShareCallbackHandler, redirect file: %s' % redirect_file)
                with open(redirect_file,'r') as f:
                    u = f.read().strip()
                    os.remove(redirect_file)
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

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        self.log.debug('HydroShareCallbackHandler, code: ' + code)
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

        self.log.debug('HydroShareCallbackHandler, url: '+str(url))

        req = HTTPRequest(url,method="POST",body='', headers={"Accept": "application/json"}, validate_cert=False,)

        resp = yield http_client.fetch(req)

        token_dict = json.loads(resp.body.decode('utf8', 'replace'))

        self.log.debug('HydroShareCallbackHandler, response json: ' + str(token_dict))

        access_token = token_dict['access_token']

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

        self.log.debug('HydroShareOAuthenticator, user: '+str(resp_json))
        
        # get the username variable from the response
        username = resp_json["username"]
        
        # save token to users home dir
        self.log.info("ENVIRON: " + str(os.environ))
        fname = os.path.join(os.environ['JUPYTER_USERSPACE_DIR_HOST'], username, '.hs_auth')
        self.log.info("fname: " + fname)
        auth = (token_dict, os.getenv('HYDROSHARE_CLIENT_ID'))
        with open(fname, 'wb') as f:
            pickle.dump(auth, f, protocol=2)

        userdict = {"name": username}
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        auth_state['github_user'] = resp_json

        return userdict
