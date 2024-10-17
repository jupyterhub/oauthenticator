"""
A JupyterHub authenticator class for use with OpenShift as an identity provider.
"""

import concurrent.futures
import json
import os

from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPClient, HTTPRequest
from traitlets import Bool, Unicode, default

from oauthenticator.oauth2 import OAuthenticator


class OpenShiftOAuthenticator(OAuthenticator):
    user_auth_state_key = "openshift_user"

    @default("auth_state_groups_key")
    def _auth_state_groups_key_default(self):
        return "openshift_user.groups"

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

        # This code run during startup when we can't yet use async
        # functionality. Due to this, Tornado's HTTPClient instead of
        # AsyncHTTPClient is used. With HTTPClient we can still re-use
        # `http_request_args` specific to Tornado's HTTP clients.
        #
        # A dedicated thread is used for HTTPClient because of
        # https://github.com/tornadoweb/tornado/issues/2325#issuecomment-375972739.
        #
        def fetch_auth_info():
            client = HTTPClient()
            req = HTTPRequest(auth_info_url, **self.http_request_kwargs)
            resp = client.fetch(req)
            resp_json = json.loads(resp.body.decode("utf8", "replace"))
            return resp_json

        with concurrent.futures.ThreadPoolExecutor(1) as executor:
            future = executor.submit(fetch_auth_info)
            return_value = future.result()
            return return_value.get("issuer")

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


class LocalOpenShiftOAuthenticator(LocalAuthenticator, OpenShiftOAuthenticator):
    """A version that mixes in local system user creation"""
