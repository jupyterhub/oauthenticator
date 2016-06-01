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

# hold on the the next_url for redirecting after authentication
next_url = None

def build_userspace(username):

    # make all usernames lowercase
    husername = username.lower()
    
    # get the jupyter username
    user = getpwnam('castro')  # todo: change to jupyter user
    group = grp.getgrnam('users')
    uid = user.pw_uid
    gid = group.gr_gid

    userspace_dir = os.environ['JUPYTER_USERSPACE_DIR'] 
    ipynb_dir = os.environ['JUPYTER_NOTEBOOK_DIR']
    # check to see if user exists
    basepath = os.path.abspath(os.path.join(userspace_dir, '%s'%husername))  
    #basepath = os.path.abspath(os.path.join('/home/castro/userspace', '%s'%husername))  # todo userspace path should be set as environment variable
    path = os.path.abspath(os.path.join(basepath, 'notebooks'))
    if not os.path.exists(path):
        os.makedirs(path)
    
    file_paths = []
    print('IPYNB_DIR: ' + ipynb_dir)
    #ipynb_dir = '../jupyter-rest-endpoint/notebooks'
    for root, dirs, files in os.walk(ipynb_dir):
        for file in files:
            file_paths.append(os.path.join(os.path.abspath(root), file))
    relpaths = [os.path.relpath(p, ipynb_dir) for p in file_paths]
    for i in range(0, len(file_paths)):
        src = file_paths[i]
        dst = os.path.join(path, relpaths[i])
        dirpath = os.path.dirname(dst)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
        print('copying: %s -> %s' %(src,dst))
        shutil.copyfile(src, dst)

    # change file ownership so that it can be accessed inside docker container
    print('Modifying permissions for %s' % basepath)
    os.chown(basepath, uid, gid)
    for root, dirs, files in os.walk(basepath):
        for d in dirs:
            print('Modifying permissions for %s' % os.path.join(root,d))
            os.chown(os.path.join(root, d), uid, gid)
        for f in files:
            print('Modifying permissions for %s' % os.path.join(root,f))
            os.chown(os.path.join(root, f), uid, gid)
        
    
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

            # build userspace
            build_userspace(username)

            self.log.info('base url: ' +self.request.uri)
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            print('CALLBACKHANDLER REDIRECTING TO: '+next_url) 

            # redirect the user to the next uri, or the server homepage
            isvalid = 'oauth_login' not in next_url
            if next_url is not None and isvalid:
                self.redirect(next_url)
            else:
                u = '%s/user/%s/tree/notebooks/Welcome.ipynb' % (self.hub.server.base_url, username)
                self.redirect(u)
#                self.redirect(url_path_join(self.hub.server.base_url, 'home'))
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



