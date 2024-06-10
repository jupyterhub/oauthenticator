"""
A JupyterHub authenticator class for use with any OAuth2 based identity provider.
"""

import os

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.traitlets import Callable
from tornado.httpclient import AsyncHTTPClient
from traitlets import Bool, Dict, Unicode, Union, default, observe

from .oauth2 import OAuthenticator


class GenericOAuthenticator(OAuthenticator):
    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "OAuth 2.0")

    claim_groups_key = Union(
        [Unicode(os.environ.get('OAUTH2_GROUPS_KEY', 'groups')), Callable()],
        config=True,
        help="""
        .. deprecated:: 17.0

        Use :attr:`auth_state_groups_key` instead.


        .. versionchanged:: 17.0

        :attr:`manage_groups` is now required to be `True` to use this functionality
        """,
    )

    # Initialize value of auth_state_groups_key based on what is in claim_groups_key
    @default('auth_state_groups_key')
    def _auth_state_groups_key_default(self):
        if callable(self.claim_groups_key):
            # Automatically wrap the claim_groups_key call so it gets what it thinks it should get
            return lambda auth_state: self.claim_groups_key(
                auth_state[self.user_auth_state_key]
            )
        else:
            return f"{self.user_auth_state_key}.{self.claim_groups_key}"

    # propagate any changes to claim_groups_key to auth_state_groups_key
    @observe("claim_groups_key")
    def _claim_groups_key_changed(self, change):
        # Emit a deprecation warning directly, without using _deprecated_oauth_aliases,
        # as it is not a direct replacement for this functionality
        self.log.warning(
            "{cls}.claim_groups_key is deprecated since OAuthenticator 17.0, use {cls}.auth_state_groups_key instead".format(
                cls=self.__class__.__name__,
            )
        )

        if change.new:
            if not self.manage_groups:
                raise ValueError(
                    f'{change.owner.__class__.__name__}.{change.name} requires {change.owner.__class__.__name__}.manage_groups to also be set'
                )

        if callable(change.new):
            # Automatically wrap the claim_gorups_key call so it gets what it thinks it should get
            self.auth_state_groups_key = lambda auth_state: self.claim_groups_key(
                auth_state[self.user_auth_state_key]
            )
        else:
            self.auth_state_groups_key = (
                f"{self.user_auth_state_key}.{self.claim_groups_key}"
            )

    @default("http_client")
    def _default_http_client(self):
        return AsyncHTTPClient(
            force_instance=True, defaults=dict(validate_cert=self.validate_server_cert)
        )

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "username_key": ("username_claim", "16.0.0"),
        "extra_params": ("token_params", "16.0.0"),
        "tls_verify": ("validate_server_cert", "16.0.2"),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    username_key = Union(
        [Unicode(), Callable()],
        config=True,
        help="""
        .. deprecated:: 16.0

           Use :attr:`username_claim`.
        """,
    )
    extra_params = Dict(
        config=True,
        help="""
        .. deprecated:: 16.0

           Use :attr:`token_params`.
        """,
    )
    tls_verify = Bool(
        config=True,
        help="""
        .. deprecated:: 16.0

           Use :attr:`validate_server_cert`.
        """,
    )


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):
    """A version that mixes in local system user creation"""
