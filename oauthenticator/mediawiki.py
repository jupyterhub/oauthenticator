"""
Custom Authenticator to use MediaWiki OAuth with JupyterHub

Requires `mwoauth` package.
"""
import json
import os
from asyncio import wrap_future
from concurrent.futures import ThreadPoolExecutor

from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from mwoauth import ConsumerToken
from mwoauth import Handshaker
from mwoauth.tokens import RequestToken
from traitlets import Any
from traitlets import Integer
from traitlets import Unicode

from oauthenticator import OAuthCallbackHandler
from oauthenticator import OAuthenticator

# Name of cookie used to pass auth token between the oauth
# login and authentication phase
AUTH_REQUEST_COOKIE_NAME = 'mw_oauth_request_token_v2'

# Helpers to jsonify/de-jsonify request_token
# It is a named tuple with bytestrings, json.dumps balks
def jsonify(request_token):
    return json.dumps(
        [
            request_token.key,
            request_token.secret,
        ]
    )


def dejsonify(js):
    key, secret = json.loads(js)
    return RequestToken(key, secret)


class MWLoginHandler(BaseHandler):
    async def get(self):
        consumer_token = ConsumerToken(
            self.authenticator.client_id,
            self.authenticator.client_secret,
        )

        handshaker = Handshaker(self.authenticator.mw_index_url, consumer_token)

        redirect, request_token = await wrap_future(
            self.authenticator.executor.submit(handshaker.initiate)
        )

        self.set_secure_cookie(
            AUTH_REQUEST_COOKIE_NAME,
            jsonify(request_token),
            expires_days=1,
            path=url_path_join(self.base_url, 'hub', 'oauth_callback'),
            httponly=True,
        )
        self.log.info('oauth redirect: %r', redirect)

        self.redirect(redirect)


class MWCallbackHandler(OAuthCallbackHandler):
    """
    Override OAuthCallbackHandler to take out state parameter handling.

    mwoauth doesn't seem to support it for now!
    """

    def check_arguments(self):
        pass

    def get_state_url(self):
        return None


class MWOAuthenticator(OAuthenticator):
    login_service = 'MediaWiki'
    login_handler = MWLoginHandler
    callback_handler = MWCallbackHandler

    mw_index_url = Unicode(
        os.environ.get('MW_INDEX_URL', 'https://meta.wikimedia.org/w/index.php'),
        config=True,
        help='Full path to index.php of the MW instance to use to log in',
    )

    executor_threads = Integer(
        12,
        help="""Number of executor threads.

        MediaWiki OAuth requests happen in this thread,
        so it is mostly waiting for network replies.
        """,
        config=True,
    )
    executor = Any()

    def normalize_username(self, username):
        """
        Override normalize_username to avoid lowercasing usernames
        """
        return username

    def _executor_default(self):
        return ThreadPoolExecutor(self.executor_threads)

    async def authenticate(self, handler, data=None):
        consumer_token = ConsumerToken(
            self.client_id,
            self.client_secret,
        )

        handshaker = Handshaker(self.mw_index_url, consumer_token)
        request_token = dejsonify(handler.get_secure_cookie(AUTH_REQUEST_COOKIE_NAME))
        handler.clear_cookie(AUTH_REQUEST_COOKIE_NAME)
        access_token = await wrap_future(
            self.executor.submit(
                handshaker.complete, request_token, handler.request.query
            )
        )

        identity = await wrap_future(
            self.executor.submit(handshaker.identify, access_token)
        )
        if identity and 'username' in identity:
            # this shouldn't be necessary anymore,
            # but keep for backward-compatibility
            return {
                'name': identity['username'].replace(' ', '_'),
                'auth_state': {
                    'ACCESS_TOKEN_KEY': access_token.key,
                    'ACCESS_TOKEN_SECRET': access_token.secret,
                    'MEDIAWIKI_USER_IDENTITY': identity,
                },
            }
        else:
            self.log.error("No username found in %s", identity)
