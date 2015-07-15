"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator, LocalAuthenticator
from jupyterhub.utils import url_path_join

from traitlets import Unicode


class GitHubMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"


class BitBucketMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://bitbucket.org/site/oauth2/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"


class OAuthLoginHandler(BaseHandler):

    def get(self):
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
            scope=[],
            response_type='code')


class GitHubLoginHandler(OAuthLoginHandler, GitHubMixin):
    pass


class BitBucketLoginHandler(OAuthLoginHandler, BitBucketMixin):
    pass


class GitHubOAuthHandler(BaseHandler):

    @gen.coroutine
    def get(self):
        # TODO: Check if state argument needs to be checked
        username = yield self.authenticator.authenticate(self)
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)


class BitBucketOAuthHandler(GitHubOAuthHandler):
    pass


class GitHubOAuthenticator(Authenticator):

    login_service = "GitHub"
    oauth_callback_url = Unicode('', config=True)
    client_id = Unicode(os.environ.get('GITHUB_CLIENT_ID', ''),
                        config=True)
    client_secret = Unicode(os.environ.get('GITHUB_CLIENT_SECRET', ''),
                            config=True)

    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')

    def get_handlers(self, app):
        return [
            (r'/oauth_login', GitHubLoginHandler),
            (r'/oauth_callback', GitHubOAuthHandler),
        ]

    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/

        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code
        )

        url = url_concat("https://github.com/login/oauth/access_token",
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body=''  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "token {}".format(access_token)
                   }
        req = HTTPRequest("https://api.github.com/user",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["login"]
        if self.whitelist and username not in self.whitelist:
            username = None
        raise gen.Return(username)


class BitBucketOAuthenticator(Authenticator):

    login_service = "BitBucket"
    oauth_callback_url = Unicode(os.environ.get('OAUTH_CALLBACK_URL', ''),
                                 config=True)
    client_id = Unicode(os.environ.get('BITBUCKET_CLIENT_ID', ''),
                        config=True)
    client_secret = Unicode(os.environ.get('BITBUCKET_CLIENT_SECRET', ''),
                            config=True)

    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')

    def get_handlers(self, app):
        return [
            (r'/oauth_login', BitBucketLoginHandler),
            (r'/oauth_callback', BitBucketOAuthHandler),
        ]

    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="authorization_code",
            code=code,
            redirect_uri=self.oauth_callback_url
        )

        url = url_concat(
            "https://bitbucket.org/site/oauth2/access_token", params)
        self.log.info(url)

        bb_header = {"Content-Type":
                     "application/x-www-form-urlencoded;charset=utf-8"}
        req = HTTPRequest(url,
                          method="POST",
                          auth_username=self.client_id,
                          auth_password=self.client_secret,
                          body=urllib.parse.urlencode(params).encode('utf-8'),
                          headers=bb_header
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)
                   }
        req = HTTPRequest("https://api.bitbucket.org/2.0/user",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["username"]
        if self.whitelist and username not in self.whitelist:
            username = None
        raise gen.Return(username)


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):

    """A version that mixes in local system user creation"""
    pass


class LocalBitBucketOAuthenticator(LocalAuthenticator,
                                   BitBucketOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
