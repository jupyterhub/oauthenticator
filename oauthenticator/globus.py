"""
Custom Authenticator to use Globus OAuth2 with JupyterHub
"""
import os
import pickle
import base64

from tornado import gen, web
from tornado.auth import OAuth2Mixin
from tornado.concurrent import return_future
from tornado.web import HTTPError

from traitlets import List, Unicode, Bool
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthenticator, OAuthCallbackHandler


try:
    import globus_sdk
except:
    raise ImportError('globus_sdk is not installed, please see '
                      '"globus-requirements.txt" for using Globus oauth.')


class GlobusMixin(OAuth2Mixin):
    """
    Use the globus_sdk to get the auth URL.
    """
    @return_future
    def authorize_redirect(self, client=None, callback=None):
        self.redirect(client.oauth2_get_authorize_url())
        callback()


class GlobusOAuthCallbackHandler(OAuthCallbackHandler):
    """This extra callback handler is needed to store transfer tokens
    in auth_state. This is needed since there isn't a sensible way to
    access the database through `authenticate`, although this may change
    with the following issue:
    https://github.com/jupyterhub/jupyterhub/issues/1063
    globus tokens are saved in the database to persist server
    restarts and closed browser windows. This ensures consistency -- whenever
    the user is logged in, they will be able to spawn a notebook with tokens.
    """
    @gen.coroutine
    def get(self):
        username = yield self.authenticator.get_authenticated_user(self, None)

        if username:
            user = self.user_from_username(username)
            self.set_globus_data(user)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            raise web.HTTPError(403)

    def set_globus_data(self, user):
        user.auth_state = {
            'globus_data': self.authenticator.globus_data
        }
        self.db.commit()


class GlobusLoginHandler(OAuthLoginHandler, GlobusMixin):
    """
    The login handler sets the scope and provides the redirect URL.
    The scope can be modified from the config.
    """

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        client = self.authenticator.globus_portal_client()
        client.oauth2_start_flow(
            redirect_uri,
            requested_scopes=' '.join(self.authenticator.scope),
            refresh_tokens=self.authenticator.allow_refresh_tokens
        )
        self.log.info('globus redirect: %r', redirect_uri)
        self.authorize_redirect(client)


class GlobusOAuthenticator(OAuthenticator):
    """The Globus OAuthenticator handles both authorization and passing
    transfer tokens to the spawner. """

    login_service = 'Globus'
    login_handler = GlobusLoginHandler
    callback_handler = GlobusOAuthCallbackHandler

    identity_provider = Unicode(help="""Restrict which institution a user
    can use to login (GlobusID, University of Hogwarts, etc.). This should
    be set in the app at developers.globus.org, but this acts as an additional
    check to prevent unnecessary account creation.""").tag(config=True)

    def _identity_provider_default(self):
        return os.getenv('IDENTITY_PROVIDER', 'globusid.org')

    exclude_tokens = List(
        help="""Exclude tokens from being passed into user environments
        when they start notebooks, Terminals, etc."""
    ).tag(config=True)

    def _exclude_tokens_default(self):
        return ['auth.globus.org']

    scope = List(
        help="""Set scope for Globus Auth. The transfer scope can be removed in
         which case a transfer token will no longer be passed to the spawner.
         Alternatively, add additional transfer scopes and those transfer
         tokens will automatically be added."""
    ).tag(config=True)

    def _scope_default(self):
        return [
            'openid',
            'profile',
            'urn:globus:auth:scope:transfer.api.globus.org:all'
        ]

    allow_refresh_tokens = Bool(
        help="""Allow users to have Refresh Tokens. If Refresh Tokens are not
        allowed, users must use regular Access Tokens which will expire after
        a set time. Set to False for increased security, True for increased
        convenience."""
    ).tag(config=True)

    def _allow_refresh_tokens_default(self):
        return True

    globus_local_endpoint = Unicode(help="""If Jupyterhub is also a Globus
    endpoint, its endpoint id can be specified here.""").tag(config=True)

    def _globus_local_endpoint_default(self):
        return os.getenv('GLOBUS_LOCAL_ENDPOINT', '')

    def pre_spawn_start(self, user, spawner):
        """Add tokens to the spawner whenever the spawner starts a notebook.
        This will allow users to create a transfer client:
        globus-sdk-python.readthedocs.io/en/stable/tutorial/#tutorial-step4
        """
        if self.globus_local_endpoint:
            spawner.environment.update(
                {'GLOBUS_LOCAL_ENDPOINT': self.globus_local_endpoint}
            )
        if user.auth_state.get('globus_data'):
            globus_data = base64.b64encode(
                pickle.dumps(user.auth_state['globus_data'])
            )
            spawner.environment['GLOBUS_DATA'] = globus_data
        else:
            # This can happen when migrating old users with a valid
            # Jupyterhub session that have never used this oauthenticator
            self.log.error('Globus data not found, user will not be able '
                           'to start transfers until they '
                           're-authenticate.')

    def globus_portal_client(self):
        return globus_sdk.ConfidentialAppAuthClient(
            self.client_id,
            self.client_secret)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.globus_data = {}

    @gen.coroutine
    def authenticate(self, handler, data=None):
        """
        Authenticate with globus.org. Usernames (and therefore Jupyterhub
        accounts) will correspond to a Globus User ID, so foouser@globusid.org
        will have the 'foouser' account in Jupyterhub.
        """
        code = handler.get_argument("code")
        redirect_uri = self.get_callback_url(self)

        client = self.globus_portal_client()
        client.oauth2_start_flow(
            redirect_uri,
            requested_scopes=' '.join(self.scope),
            refresh_tokens=self.allow_refresh_tokens
        )
        # Doing the code for token for id_token exchange
        tokens = client.oauth2_exchange_code_for_tokens(code)
        self.globus_data['tokens'] = {
            tok: v for tok, v in tokens.by_resource_server.items()
            if tok not in self.exclude_tokens
        }

        self.globus_data['client_id'] = self.client_id
        id_token = tokens.decode_id_token(client)
        username, domain = id_token.get('preferred_username').split('@')

        if self.identity_provider and domain != self.identity_provider:
            raise HTTPError(
                403,
                'This site is restricted to {} accounts. Please link your {}'
                ' account at {}.'.format(
                    self.identity_provider,
                    self.identity_provider,
                    'globus.org/app/account'
                    )
            )
        return username

    def get_callback_url(self, handler=None):
        """
        Getting the configured callback url
        """
        if self.oauth_callback_url is None:
            raise HTTPError(500,
                            'No callback url provided. '
                            'Please configure by adding '
                            'c.GlobusOAuthenticator.oauth_callback_url '
                            'to the config'
                            )
        return self.oauth_callback_url


class LocalGlobusOAuthenticator(LocalAuthenticator, GlobusOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
