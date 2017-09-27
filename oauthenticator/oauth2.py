"""
Base classes for Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""

import base64
import json
import os
import uuid

from tornado import gen, web
from tornado.log import app_log

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from traitlets import Unicode, Bool, List


def guess_callback_uri(protocol, host, hub_server_url):
    return '{proto}://{host}{path}'.format(
        proto=protocol,
        host=host,
        path=url_path_join(
            hub_server_url,
            'oauth_callback'
        )
    )

STATE_COOKIE_NAME = 'oauthenticator-state'


def _serialize_state(state):
    """Serialize OAuth state to a base64 string after passing through JSON"""
    json_state = json.dumps(state)
    return base64.urlsafe_b64encode(
        json_state.encode('utf8')
    ).decode('ascii')


def _deserialize_state(b64_state):
    """Deserialize OAuth state as serialized in _serialize_state"""
    if isinstance(b64_state, str):
        b64_state = b64_state.encode('ascii')
    try:
        json_state = base64.urlsafe_b64decode(b64_state).decode('utf8')
    except ValueError:
        app_log.error("Failed to b64-decode state: %r", b64_state)
        return {}
    try:
        return json.loads(json_state)
    except ValueError:
        app_log.error("Failed to json-decode state: %r", json_state)
        return {}


class OAuthLoginHandler(BaseHandler):
    """Base class for OAuth login handler

    Typically subclasses will need
    """

    def set_state_cookie(self, state):
        self.set_secure_cookie(STATE_COOKIE_NAME,
            state, expires_days=1, httponly=True,
        )

    _state = None
    def get_state(self):
        next_url = self.get_argument('next', None)
        if self._state is None:
            self._state = _serialize_state({
                'state_id': uuid.uuid4().hex,
                'next_url': next_url,
            })
        return self._state

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        self.log.info('OAuth redirect: %r', redirect_uri)
        state = self.get_state()
        self.set_state_cookie(state)
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=self.authenticator.scope,
            extra_params={'state': state},
            response_type='code')


class OAuthCallbackHandler(BaseHandler):
    """Basic handler for OAuth callback. Calls authenticator to verify username."""

    _state_cookie = None

    def get_state_cookie(self):
        """Get OAuth state from cookies

        To be compared with the value in redirect URL
        """
        if self._state_cookie is None:
            self._state_cookie = (self.get_secure_cookie(STATE_COOKIE_NAME) or b'').decode('utf8', 'replace')
            self.clear_cookie(STATE_COOKIE_NAME)
        return self._state_cookie

    def get_state_url(self):
        """Get OAuth state from URL parameters

        to be compared with the value in cookies
        """
        return self.get_argument("state")

    def check_state(self):
        """Verify OAuth state

        compare value in cookie with redirect url param
        """
        cookie_state = self.get_state_cookie()
        url_state = self.get_state_url()
        if not cookie_state:
            raise web.HTTPError(400, "OAuth state missing from cookies")
        if not url_state:
            raise web.HTTPError(400, "OAuth state missing from URL")
        if cookie_state != url_state:
            self.log.warning("OAuth state mismatch: %s != %s", cookie_state, url_state)
            raise web.HTTPError(400, "OAuth state mismatch")
    
    def check_code(self):
        """Check the OAuth code"""
        if not self.get_argument("code", False):
            raise web.HTTPError(400, "OAuth callback made without a code")
    
    def check_arguments(self):
        """Validate the arguments of the redirect
        
        Default:
        
        - check that there's a code
        - check that state matches 
        """
        self.check_code()
        self.check_state()

    def get_next_url(self, user=None):
        """Get the redirect target from the state field"""
        state = self.get_state_url()
        if state:
            next_url = _deserialize_state(state).get('next_url')
            if next_url:
                return next_url
        # JupyterHub 0.8 adds default .get_next_url for a fallback
        if hasattr(BaseHandler, 'get_next_url'):
            return super().get_next_url(user)
        return url_path_join(self.hub.server.base_url, 'home')

    @gen.coroutine
    def _login_user_pre_08(self):
        """login_user simplifies the login+cookie+auth_state process in JupyterHub 0.8

        _login_user_07 is for backward-compatibility with JupyterHub 0.7
        """
        user_info = yield self.authenticator.get_authenticated_user(self, None)
        if user_info is None:
            return
        if isinstance(user_info, dict):
            username = user_info['name']
        else:
            username = user_info
        user = self.user_from_username(username)
        self.set_login_cookie(user)
        return user

    if not hasattr(BaseHandler, 'login_user'):
        # JupyterHub 0.7 doesn't have .login_user
        login_user = _login_user_pre_08

    @gen.coroutine
    def get(self):
        self.check_arguments()
        user = yield self.login_user()
        if user is None:
            # todo: custom error page?
            raise web.HTTPError(403)
        self.redirect(self.get_next_url(user))


class OAuthenticator(Authenticator):
    """Base class for OAuthenticators

    Subclasses must override:

    login_service (string identifying the service provider)
    login_handler (likely a subclass of OAuthLoginHandler)
    authenticate (method takes one arg - the request handler handling the oauth callback)
    """

    scope = List(Unicode(), config=True,
        help="""The OAuth scopes to request.
        See the OAuth documentation of your OAuth provider for options.
        For GitHub in particular, you can see github_scopes.md in this repo.
        """
    )

    login_service = 'override in subclass'
    oauth_callback_url = Unicode(
        os.getenv('OAUTH_CALLBACK_URL', ''),
        config=True,
        help="""Callback URL to use.
        Typically `https://{host}/hub/oauth_callback`"""
    )

    client_id_env = ''
    client_id = Unicode(config=True)
    def _client_id_default(self):
        if self.client_id_env:
            client_id = os.getenv(self.client_id_env, '')
            if client_id:
                return client_id
        return os.getenv('OAUTH_CLIENT_ID', '')

    client_secret_env = ''
    client_secret = Unicode(config=True)
    def _client_secret_default(self):
        if self.client_secret_env:
            client_secret = os.getenv(self.client_secret_env, '')
            if client_secret:
                return client_secret
        return os.getenv('OAUTH_CLIENT_SECRET', '')

    validate_server_cert_env = 'OAUTH_TLS_VERIFY'
    validate_server_cert = Bool(config=True)
    def _validate_server_cert_default(self):
        env_value = os.getenv(self.validate_server_cert_env, '')
        if env_value == '0':
            return False
        else:
            return True

    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')

    login_handler = "Specify login handler class in subclass"
    callback_handler = OAuthCallbackHandler
    
    def get_callback_url(self, handler=None):
        """Get my OAuth redirect URL
        
        Either from config or guess based on the current request.
        """
        if self.oauth_callback_url:
            return self.oauth_callback_url
        elif handler:
            return guess_callback_uri(
                handler.request.protocol,
                handler.request.host,
                handler.hub.server.base_url
            )
        else:
            raise ValueError("Specify callback oauth_callback_url or give me a handler to guess with")

    def get_handlers(self, app):
        return [
            (r'/oauth_login', self.login_handler),
            (r'/oauth_callback', self.callback_handler),
        ]

    @gen.coroutine
    def authenticate(self, handler, data=None):
        raise NotImplementedError()
