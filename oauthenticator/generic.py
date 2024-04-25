"""
A JupyterHub authenticator class for use with any OAuth2 based identity provider.
"""

import os
from functools import reduce

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.traitlets import Callable
from tornado.httpclient import AsyncHTTPClient
from traitlets import Bool, Dict, Set, Unicode, Union, default

from .oauth2 import OAuthenticator


class GenericOAuthenticator(OAuthenticator):
    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "OAuth 2.0")

    claim_groups_key = Union(
        [Unicode(os.environ.get('OAUTH2_GROUPS_KEY', 'groups')), Callable()],
        config=True,
        help="""
        Userdata groups claim key from returned json for USERDATA_URL.

        Can be a string key name (use periods for nested keys), or a callable
        that accepts the returned json (as a dict) and returns the groups list.

        This configures how group membership in the upstream provider is determined
        for use by `allowed_groups`, `admin_groups`, etc. If `manage_groups` is True,
        this will also determine users' _JupyterHub_ group membership.
        """,
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

    def get_user_groups(self, user_info):
        """
        Returns a set of groups the user belongs to based on claim_groups_key
        and provided user_info.

        - If claim_groups_key is a callable, it is meant to return the groups
          directly.
        - If claim_groups_key is a nested dictionary key like
          "permissions.groups", this function returns
          user_info["permissions"]["groups"].

        Note that this method is introduced by GenericOAuthenticator and not
        present in the base class.
        """
        if callable(self.claim_groups_key):
            return set(self.claim_groups_key(user_info))
        try:
            return set(reduce(dict.get, self.claim_groups_key.split("."), user_info))
        except TypeError:
            self.log.error(
                f"The claim_groups_key {self.claim_groups_key} does not exist in the user token"
            )
            return set()


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):
    """A version that mixes in local system user creation"""
