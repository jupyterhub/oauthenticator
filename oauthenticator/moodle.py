"""
Custom Authenticator for Moodle to use OAuth2 with JupyterHub.
Configured for use with Moodle OAuth2 Server Plugin from
https://github.com/projectestac/moodle-local_oauth .
"""


import json
import os
import base64
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict

from .oauth2 import OAuthLoginHandler, OAuthenticator


class MoodleEnvMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL', '')
    _OAUTH_AUTHORIZE_URL = os.environ.get('OAUTH2_AUTHORIZE_URL', '')


class MoodleLoginHandler(OAuthLoginHandler, MoodleEnvMixin):
    pass


class MoodleOAuthenticator(OAuthenticator):

    login_service = Unicode(
        "Moodle",
        config=True
    )

    login_handler = MoodleLoginHandler

    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL', ''),
        config=True,
        help="Userdata url to get user data login information"
    )

    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )

    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help="Access token endpoint URL"
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope='user_info'
        )

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }
        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          # Body is required for a POST...
                          body=urllib.parse.urlencode(params)
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

        req = HTTPRequest(self.userdata_url,
                          method="POST",
                          headers=headers,
                          body=urllib.parse.urlencode({'access_token': access_token})
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if not resp_json.get(self.username_key):
            self.log.error(
                "OAuth user contains no key %s: %s",
                self.username_key,
                resp_json)
            return

        return {
            'name': resp_json.get(self.username_key),
            'auth_state': {
                'access_token': access_token,
                'oauth_user': resp_json,
            }
        }


class LocalMoodleOAuthenticator(LocalAuthenticator, MoodleOAuthenticator):

    """A version that mixes in local system user creation"""
    pass