"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Yuvi Panda (@yuvipanda)
"""

import os
import json
from concurrent.futures import ThreadPoolExecutor

from tornado import gen, web

from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from jupyterhub import orm

from mwoauth import ConsumerToken, Handshaker
from mwoauth.tokens import RequestToken

from traitlets import Unicode

from oauthenticator import OAuthenticator


# Name of cookie used to pass auth token between the oauth
# login and authentication phase
AUTH_REQUEST_COOKIE_NAME = 'mw_oauth_request_token_v2'

# Helpers to jsonify/de-jsonify request_token
# It is a named tuple with bytestrings, json.dumps balks
def jsonify(request_token):
    return json.dumps([
        request_token.key.decode('utf-8'),
        request_token.secret.decode('utf-8')
    ])


def dejsonify(js):
    key, secret = json.loads(js.decode('utf-8'))
    return RequestToken(key.encode('utf-8'), secret.encode('utf-8'))


class MWLoginHandler(BaseHandler):
    @property
    def executor(self):
        if hasattr(self, '_executor'):
            return self._executor
        else:
            self._executor = ThreadPoolExecutor(max_workers=12)
            return self._executor

    @gen.coroutine
    def get(self):
        consumer_token = ConsumerToken(
            self.authenticator.client_id,
            self.authenticator.client_secret,
        )

        handshaker = Handshaker(
            self.authenticator.mw_index_url, consumer_token
        )

        redirect, request_token = yield self.executor.submit(handshaker.initiate)

        self.set_secure_cookie(
            AUTH_REQUEST_COOKIE_NAME,
            jsonify(request_token),
            expires_days=1,
            path=url_path_join(self.base_url, 'hub', 'oauth_callback'),
            httponly=True)
        self.log.info('oauth redirect: %r', redirect)

        self.redirect(redirect)


class MWOAuthHandler(BaseHandler):
    @property
    def executor(self):
        if hasattr(self, '_executor'):
            return self._executor
        else:
            self._executor = ThreadPoolExecutor(max_workers=12)
            return self._executor

    @gen.coroutine
    def get(self):
        consumer_token = ConsumerToken(
            self.authenticator.client_id,
            self.authenticator.client_secret
        )

        handshaker = Handshaker(
            self.authenticator.mw_index_url, consumer_token
        )
        request_token = dejsonify(self.get_secure_cookie(AUTH_REQUEST_COOKIE_NAME))
        self.clear_cookie(AUTH_REQUEST_COOKIE_NAME)
        access_token = yield self.executor.submit(
            handshaker.complete, request_token, self.request.query
        )

        identity = handshaker.identify(access_token)
        if identity and 'username' in identity:
            # FIXME: Figure out total set of chars that can be present
            # in MW's usernames, and set of chars valid in jupyterhub
            # usernames, and do a proper mapping
            username = identity['username'].replace(' ', '_')
            user = self.find_user(username)
            if user is None:
                user = orm.User(name=username, id=identity['sub'])
                self.db.add(user)
                self.db.commit()
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)


class MWOAuthenticator(OAuthenticator):
    login_service = 'MediaWiki'
    login_handler = MWLoginHandler

    mw_index_url = Unicode(
        os.environ.get('MW_INDEX_URL', 'https://meta.wikimedia.org/w/index.php'),
        config=True,
        help='Full path to index.php of the MW instance to use to log in'
    )

    def get_handlers(self, app):
        return [
            (r'/oauth_login', MWLoginHandler),
            (r'/oauth_callback', MWOAuthHandler),
        ]
