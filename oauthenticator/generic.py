"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""
import os
from functools import reduce

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.traitlets import Callable
from tornado.httpclient import AsyncHTTPClient
from traitlets import Bool, Dict, Set, Unicode, Union, default

from .oauth2 import OAuthenticator


class GenericOAuthenticator(OAuthenticator):
    _deprecated_oauth_aliases = {
        "username_key": ("username_claim", "16.0.0"),
        "extra_params": ("token_params", "16.0.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    extra_params = Dict(
        help="Deprecated, use `GenericOAuthenticator.token_params`"
    ).tag(config=True)

    login_service = Unicode("OAuth 2.0", config=True)

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
        help="Automatically allow members of selected groups",
    )

    admin_groups = Set(
        Unicode(),
        config=True,
        help="Groups whose members should have Jupyterhub admin privileges",
    )

    username_key = Union(
        [Unicode(os.environ.get('OAUTH2_USERNAME_KEY', 'username')), Callable()],
        config=True,
        help="""Deprecated, use `GenericOAuthenticator.username_claim`""",
    )

    username_claim = Union(
        [Unicode(os.environ.get('OAUTH2_USERNAME_KEY', 'username')), Callable()],
        config=True,
        help="""
        Userdata username key from returned json for USERDATA_URL.

        Can be a string key name or a callable that accepts the returned
        json (as a dict) and returns the username.  The callable is useful
        e.g. for extracting the username from a nested object in the
        response.
        """,
    )

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Require valid tls certificates in HTTP requests",
    )

    @default("basic_auth")
    def _basic_auth_default(self):
        return os.environ.get('OAUTH2_BASIC_AUTH', 'True').lower() in {'true', '1'}

    @default("http_client")
    def _default_http_client(self):
        return AsyncHTTPClient(
            force_instance=True, defaults=dict(validate_cert=self.tls_verify)
        )

    def user_info_to_username(self, user_info):
        if callable(self.username_claim):
            username = self.username_claim(user_info)
        else:
            username = user_info.get(self.username_claim, None)
            if not username:
                message = (f"No {self.username_claim} found in {user_info}",)
                self.log.error(message)
                raise ValueError(message)

        return username

    def get_user_groups(self, user_info):
        """
        Returns a set of groups the user belongs to based on claim_groups_key
        and provided user_info.

        - If claim_groups_key is a callable, it is meant to return the groups
          directly.
        - If claim_groups_key is a nested dictionary key like
          "permissions.groups", this function returns
          user_info["permissions"]["groups"].
        """
        if callable(self.claim_groups_key):
            return set(self.claim_groups_key(user_info))
        try:
            return reduce(dict.get, self.claim_groups_key.split("."), user_info)
        except TypeError:
            self.log.error(
                f"The claim_groups_key {self.claim_groups_key} does not exist in the user token"
            )
            return set()

    async def update_auth_model(self, auth_model):
        """
        Set the admin status based on finding the username in `admin_users` or
        finding a user group part of `admin_groups`.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]

        username = auth_model["name"]
        if username in self.admin_users:
            auth_model["admin"] = True
        elif self.admin_groups:
            # if admin_groups is configured, we must either set or unset admin
            # status and never leave it at None, otherwise removing a user from
            # the admin_groups won't have an effect
            user_groups = self.get_user_groups(user_info)
            auth_model["admin"] = any(user_groups & self.admin_groups)

        return auth_model

    async def check_allowed(self, username, auth_model):
        """
        Returns True for users allowed to be authorized.

        Overrides the OAuthenticator.check_allowed implementation to allow users
        either part of `allowed_users` or `allowed_groups`, and not just those
        part of `allowed_users`.
        """
        # allow admin users recognized via admin_users or update_auth_model
        if auth_model["admin"]:
            return True

        # if allowed_users or allowed_groups is configured, we deny users not
        # part of either
        if self.allowed_users or self.allowed_groups:
            user_info = auth_model["auth_state"][self.user_auth_state_key]
            user_groups = self.get_user_groups(user_info)
            if username in self.allowed_users:
                return True
            if any(user_groups & self.allowed_groups):
                return True
            return False

        # otherwise, authorize all users
        return True


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):
    """A version that mixes in local system user creation"""
