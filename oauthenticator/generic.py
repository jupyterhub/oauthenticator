"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""
import os
from functools import reduce

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.traitlets import Callable
from tornado.httpclient import AsyncHTTPClient
from traitlets import Bool, Dict, List, Unicode, Union, default

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

    allowed_groups = List(
        Unicode(),
        config=True,
        help="Automatically allow members of selected groups",
    )

    admin_groups = List(
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
        help="Disable TLS verification on http request",
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
        if callable(self.claim_groups_key):
            groups = self.claim_groups_key(user_info)
        else:
            try:
                groups = reduce(dict.get, self.claim_groups_key.split("."), user_info)
            except TypeError:
                # This happens if a nested key does not exist (reduce trying to call None.get)
                self.log.error(
                    f"The key {self.claim_groups_key} does not exist in the user token, or it is set to null"
                )
                groups = None

        if not groups:
            self.log.error(
                f"No claim groups found for user! Something wrong with the `claim_groups_key` {self.claim_groups_key}? {user_info}"
            )
        return groups

    async def user_is_authorized(self, auth_model):
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        if self.allowed_groups:
            self.log.info(
                f"Validating if user claim groups match any of {self.allowed_groups}"
            )

            groups = self.get_user_groups(user_info)
            if not groups:
                return False

            all_allowed_groups = self.allowed_groups
            if self.admin_groups:
                all_allowed_groups += self.admin_groups
            if not self.user_groups_in_allowed_groups(
                groups, all_allowed_groups
            ):
                return False

        return True

    async def update_auth_model(self, auth_model):
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        admin_status = True if auth_model['name'] in self.admin_users else None
        # Check if user has been marked as admin by membership in self.admin_groups
        if not admin_status and self.admin_groups:
            groups = self.get_user_groups(user_info)
            if groups:
                auth_model['admin'] = self.user_groups_in_allowed_groups(
                    groups, self.admin_groups
                )

        return auth_model


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):
    """A version that mixes in local system user creation"""
