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

from tornado.escape import url_escape
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support gitlab.com and gitlab community edition installations
GITLAB_HOST = os.environ.get('GITLAB_HOST') or 'https://gitlab.com'
GITLAB_API_VERSION = os.environ.get('GITLAB_API_VERSION') or '4'
GITLAB_API = '%s/api/v%s' % (GITLAB_HOST, GITLAB_API_VERSION)


def _api_headers(access_token):
    return {"Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token)
           }


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

    gitlab_group_whitelist = Set(
        config=True,
        help="Automatically whitelist members of selected groups",
    )


    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
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
            redirect_uri=self.get_callback_url(handler),
        )


        validate_server_cert = self.validate_server_cert

        url = url_concat("%s/oauth/token" % GITLAB_HOST,
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          validate_cert=validate_server_cert,
                          body='' # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        req = HTTPRequest("%s/user" % GITLAB_API,
                          method="GET",
                          validate_cert=validate_server_cert,
                          headers=_api_headers(access_token)
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["username"]
        user_id = resp_json["id"]
        is_admin = resp_json.get("is_admin", False)

        # Check if user is a member of any whitelisted organizations.
        # This check is performed here, as it requires `access_token`.
        if self.gitlab_group_whitelist:
            user_in_group = yield self._check_group_whitelist(
                username, user_id, is_admin, access_token)
            if not user_in_group:
                self.log.warning("%s not in group whitelist", username)
                return None
        return {
            'name': username,
            'auth_state': {
                'access_token': access_token,
                'gitlab_user': resp_json,
            }
        }


    @gen.coroutine
    def _check_group_whitelist(self, username, user_id, is_admin, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        if is_admin:
            # For admins, /groups returns *all* groups. As a workaround
            # we check if we are a member of each group in the whitelist
            for group in map(url_escape, self.gitlab_group_whitelist):
                url = "%s/groups/%s/members/%d" % (GITLAB_API, group, user_id)
                req = HTTPRequest(url, method="GET", headers=headers)
                resp = yield http_client.fetch(req, raise_error=False)
                if resp.code == 200:
                    return True  # user _is_ in group
        else:
            # For regular users we get all the groups to which they have access
            # and check if any of these are in the whitelisted groups
            next_page = url_concat("%s/groups" % GITLAB_API,
                                   dict(all_available=True))
            while next_page:
                req = HTTPRequest(next_page, method="GET", headers=headers)
                resp = yield http_client.fetch(req)
                resp_json = json.loads(resp.body.decode('utf8', 'replace'))
                next_page = next_page_from_links(resp)
                user_groups = set(entry["path"] for entry in resp_json)
                # check if any of the organizations seen thus far are in whitelist
                if len(self.gitlab_group_whitelist & user_groups) > 0:
                    return True
            return False



class LocalGitLabOAuthenticator(LocalAuthenticator, GitLabOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
