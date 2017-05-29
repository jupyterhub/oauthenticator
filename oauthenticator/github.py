"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os
import re

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Set

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com'
else:
    GITHUB_API = '%s/api/v3' % GITHUB_HOST


def _api_headers(access_token):
    return {"Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "token {}".format(access_token)
           }


class GitHubMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/login/oauth/authorize" % GITHUB_HOST
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/login/oauth/access_token" % GITHUB_HOST


class GitHubLoginHandler(OAuthLoginHandler, GitHubMixin):
    pass


class GitHubOAuthenticator(OAuthenticator):
    
    login_service = "GitHub"
    
    # deprecated names
    github_client_id = Unicode(config=True, help="DEPRECATED")
    def _github_client_id_changed(self, name, old, new):
        self.log.warn("github_client_id is deprecated, use client_id")
        self.client_id = new
    github_client_secret = Unicode(config=True, help="DEPRECATED")
    def _github_client_secret_changed(self, name, old, new):
        self.log.warn("github_client_secret is deprecated, use client_secret")
        self.client_secret = new
    
    client_id_env = 'GITHUB_CLIENT_ID'
    client_secret_env = 'GITHUB_CLIENT_SECRET'
    login_handler = GitHubLoginHandler

    github_organization_whitelist = Set(
        config=True,
        help="Automatically whitelist members of selected organizations",
    )

    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
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
        
        url = url_concat("https://%s/login/oauth/access_token" % GITHUB_HOST,
                         params)
        
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        req = HTTPRequest("https://%s/user" % GITHUB_API,
                          method="GET",
                          headers=_api_headers(access_token)
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username =  resp_json["login"]

        # Check if user is a member of any whitelisted organizations.
        # This check is performed here, as it requires `access_token`.
        if self.github_organization_whitelist:
            for org in self.github_organization_whitelist:
                user_in_org = yield self._check_organization_whitelist(org, username, access_token)
                if user_in_org:
                    return username
            else:  # User not found in member list for any organisation
                return None
        else:  # no organization whitelisting
            return username


    @gen.coroutine
    def _check_organization_whitelist(self, org, username, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        # Get all the members for organization 'org'
        next_page = "https://%s/orgs/%s/members" % (GITHUB_API, org)
        while next_page:
            req = HTTPRequest(next_page, method="GET", headers=headers)
            resp = yield http_client.fetch(req)
            resp_json = json.loads(resp.body.decode('utf8', 'replace'))
            next_page = next_page_from_links(resp)
            org_members = set(entry["login"] for entry in resp_json)
            # check if any of the organizations seen thus far are in whitelist
            if username in org_members:
                return True
        return False



class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):

    """A version that mixes in local system user creation"""
    pass

