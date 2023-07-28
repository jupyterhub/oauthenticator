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
        """,
    )

    allowed_groups = Set(
        Unicode(),
        config=True,
        help="""
        Allow members of selected groups to sign in.

        When configuring this you may need to configure `claim_groups_key` as
        well as it determines the key in the `userdata_url` response that is
        assumed to list the groups a user is a member of.
        """,
    )

    admin_groups = Set(
        Unicode(),
        config=True,
        help="""
        Allow members of selected groups to sign in and consider them as
        JupyterHub admins.

        If this is set and a user isn't part of one of these groups or listed in
        `admin_users`, a user signing in will have their admin status revoked.

        When configuring this you may need to configure `claim_groups_key` as
        well as it determines the key in the `userdata_url` response that is
        assumed to list the groups a user is a member of.
        """,
    )

    username_claim = Union(
        [Unicode(os.environ.get('OAUTH2_USERNAME_KEY', 'username')), Callable()],
        config=True,
        help="""
        When `userdata_url` returns a json response, the username will be taken
        from this key.

        Can be a string key name or a callable that accepts the returned
        userdata json (as a dict) and returns the username.  The callable is
        useful e.g. for extracting the username from a nested object in the
        response.
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

    def user_info_to_username(self, user_info):
        """
        Overrides OAuthenticator.user_info_to_username to support the
        GenericOAuthenticator unique feature of allowing username_claim to be a
        callable function.
        """
        if callable(self.username_claim):
            return self.username_claim(user_info)
        else:
            return super().user_info_to_username(user_info)

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

    async def update_auth_model(self, auth_model):
        """
        Sets admin status to True or False if `admin_groups` is configured and
        the user isn't part of `admin_users` or `admin_groups`. Note that
        leaving it at None makes users able to retain an admin status while
        setting it to False makes it be revoked.
        """
        if auth_model["admin"]:
            # auth_model["admin"] being True means the user was in admin_users
            return auth_model

        if self.admin_groups:
            # admin status should in this case be True or False, not None
            user_info = auth_model["auth_state"][self.user_auth_state_key]
            user_groups = self.get_user_groups(user_info)
            auth_model["admin"] = any(user_groups & self.admin_groups)

        return auth_model

    async def check_allowed(self, username, auth_model):
        """
        Overrides the OAuthenticator.check_allowed to also allow users part of
        `allowed_groups`.
        """
        if await super().check_allowed(username, auth_model):
            return True

        if self.allowed_groups:
            user_info = auth_model["auth_state"][self.user_auth_state_key]
            user_groups = self.get_user_groups(user_info)
            if any(user_groups & self.allowed_groups):
                return True

        # users should be explicitly allowed via config, otherwise they aren't
        return False


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):
    """A version that mixes in local system user creation"""
