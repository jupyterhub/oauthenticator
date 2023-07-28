"""
A JupyterHub authenticator class for use with OpenShift as an identity provider.
"""
import json
import os

from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPClient, HTTPRequest
from traitlets import Bool, Set, Unicode, default

from oauthenticator.oauth2 import OAuthenticator


class OpenShiftOAuthenticator(OAuthenticator):
    user_auth_state_key = "openshift_user"

    @default("scope")
    def _scope_default(self):
        return ["user:info"]

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "OpenShift")

    @default("username_claim")
    def _username_claim_default(self):
        return "name"

    @default("http_request_kwargs")
    def _http_request_kwargs_default(self):
        ca_cert_file = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        if self.validate_server_cert and os.path.exists(ca_cert_file):
            return {"ca_certs": ca_cert_file}
        return {}

    openshift_url = Unicode(
        os.environ.get('OPENSHIFT_URL')
        or 'https://openshift.default.svc.cluster.local',
        config=True,
        help="""
        Used to determine the default values for `openshift_auth_api_url` and
        `openshift_rest_api_url`.
        """,
    )

    allowed_groups = Set(
        config=True,
        help="""
        Allow members of selected OpenShift groups to sign in.
        """,
    )

    admin_groups = Set(
        config=True,
        help="""
        Allow members of selected OpenShift groups to sign in and consider them
        as JupyterHub admins.

        If this is set and a user isn't part of one of these groups or listed in
        `admin_users`, a user signing in will have their admin status revoked.
        """,
    )

    openshift_auth_api_url = Unicode(
        config=True,
        help="""
        Used to determine the default values for `authorize_url` and
        `token_url`.

        By default, this is determined on startup by a request to the
        `openshift_url` appended with "/.well-known/oauth-authorization-server",
        where "issuer" is extracted from the response.

        For more context, see the `Obtaining Authorization Server Metadata
        section <https://datatracker.ietf.org/doc/html/rfc8414#section-3>`_ in
        an OAuth2 standard document.
        """,
    )

    @default("openshift_auth_api_url")
    def _openshift_auth_api_url_default(self):
        auth_info_url = f"{self.openshift_url}/.well-known/oauth-authorization-server"

        # Makes a request like OAuthenticator.httpfetch would but non-async as
        # this code run during startup when we can't yet use async
        # functionality.
        client = HTTPClient()
        req = HTTPRequest(auth_info_url, **self.http_request_kwargs)
        resp = client.fetch(req)
        resp_json = json.loads(resp.body.decode("utf8", "replace"))

        return resp_json.get('issuer')

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"{self.openshift_auth_api_url}/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"{self.openshift_auth_api_url}/oauth/token"

    openshift_rest_api_url = Unicode(
        config=True,
        help="""
        Used to determine the default value for `userdata_url`.

        Defaults to the `openshift_url`.
        """,
    )

    @default("openshift_rest_api_url")
    def _openshift_rest_api_url_default(self):
        return self.openshift_url

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"{self.openshift_rest_api_url}/apis/user.openshift.io/v1/users/~"

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "ca_certs": ("http_request_kwargs", "16.0.0", False),
        "validate_cert": ("validate_server_cert", "16.0.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    ca_certs = Unicode(
        config=True,
        help="""
        .. versionremoved:: 16.0

           Use :attr:`http_request_kwargs`.
        """,
    )
    validate_cert = Bool(
        config=True,
        help="""
        .. deprecated:: 16.0

           Use :attr:`validate_server_cert`.
        """,
    )

    def user_info_to_username(self, user_info):
        """
        Overrides OAuthenticator.user_info_to_username instead of setting
        username_claim as the username is nested inside another dictionary.
        """
        return user_info['metadata']['name']

    async def update_auth_model(self, auth_model):
        """
        Sets admin status to True or False if `admin_groups` is configured and
        the user isn't part of `admin_users`. Note that leaving it at None makes
        users able to retain an admin status while setting it to False makes it
        be revoked.
        """
        if auth_model["admin"]:
            # auth_model["admin"] being True means the user was in admin_users
            return auth_model

        if self.admin_groups:
            # admin status should in this case be True or False, not None
            user_info = auth_model["auth_state"][self.user_auth_state_key]
            user_groups = set(user_info["groups"])
            auth_model["admin"] = any(user_groups & self.admin_groups)

        return auth_model

    async def check_allowed(self, username, auth_model):
        """
        Overrides OAuthenticator.check_allowed to also allow users part of
        `allowed_groups`.
        """
        if await super().check_allowed(username, auth_model):
            return True

        if self.allowed_groups:
            user_info = auth_model["auth_state"][self.user_auth_state_key]
            user_groups = set(user_info["groups"])
            if any(user_groups & self.allowed_groups):
                return True

        # users should be explicitly allowed via config, otherwise they aren't
        return False


class LocalOpenShiftOAuthenticator(LocalAuthenticator, OpenShiftOAuthenticator):
    """A version that mixes in local system user creation"""
