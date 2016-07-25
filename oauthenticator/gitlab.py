"""
Custom Authenticator to use GitLab OAuth with JupyterHub

Modified for GitLab by Laszlo Dobos (@dobos)
based on the GitHub plugin by Kyle Kelley (@rgbkrk) 
"""


import json
import os
import sys

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support gitlab.com and gitlab community edition installations
GITLAB_HOST = os.environ.get('GITLAB_HOST') or 'https://gitlab.com'
GITLAB_API = '%s/api/v3/user' % GITLAB_HOST

class GitLabMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "%s/oauth/authorize" % GITLAB_HOST
    _OAUTH_ACCESS_TOKEN_URL = "%s/oauth/access_token" % GITLAB_HOST


class GitLabLoginHandler(OAuthLoginHandler, GitLabMixin):
    pass


class GitLabOAuthenticator(OAuthenticator):
    
    login_service = "GitLab"
        
    client_id_env = 'GITLAB_CLIENT_ID'
    client_secret_env = 'GITLAB_CLIENT_SECRET'
    login_handler = GitLabLoginHandler
    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
        
        # Exchange the OAuth code for a GitLab Access Token
        #
        # See: https://github.com/gitlabhq/gitlabhq/blob/master/doc/api/oauth2.md
        
        # GitLab specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            grant_type="authorization_code",
            redirect_uri=self.oauth_callback_url
        )
        
        url = url_concat("%s/oauth/token" % GITLAB_HOST,
                         params)
        
        print(url, file=sys.stderr)
        
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
        }
        req = HTTPRequest("%s?access_token=%s" % (GITLAB_API, access_token),
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["username"]


class LocalGitLabOAuthenticator(LocalAuthenticator, GitLabOAuthenticator):

    """A version that mixes in local system user creation"""
    pass

