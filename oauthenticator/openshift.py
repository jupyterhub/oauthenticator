"""
Custom Authenticator to use OpenShift OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""
import os

import requests
from jupyterhub.auth import LocalAuthenticator
from traitlets import Bool, Set, Unicode, default

from oauthenticator.oauth2 import OAuthenticator


class OpenShiftOAuthenticator(OAuthenticator):
    login_service = "OpenShift"

    scope = ['user:info']

    user_auth_state_key = "openshift_user"

    @default("username_claim")
    def _username_claim_default(self):
        return "name"

    openshift_url = Unicode(
        os.environ.get('OPENSHIFT_URL')
        or 'https://openshift.default.svc.cluster.local',
        config=True,
    )

    validate_cert = Bool(
        True, config=True, help="Set to False to disable certificate validation"
    )

    ca_certs = Unicode(config=True)

    allowed_groups = Set(
        config=True,
        help="Set of OpenShift groups that should be allowed to access the hub.",
    )

    admin_groups = Set(
        config=True,
        help="Set of OpenShift groups that should be given admin access to the hub.",
    )

    @default("ca_certs")
    def _ca_certs_default(self):
        ca_cert_file = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        if self.validate_cert and os.path.exists(ca_cert_file):
            return ca_cert_file

        return ''

    openshift_auth_api_url = Unicode(config=True)

    @default("openshift_auth_api_url")
    def _openshift_auth_api_url_default(self):
        auth_info_url = f"{self.openshift_url}/.well-known/oauth-authorization-server"

        resp = requests.get(auth_info_url, verify=self.ca_certs or self.validate_cert)
        resp_json = resp.json()

        return resp_json.get('issuer')

    openshift_rest_api_url = Unicode(
        os.environ.get('OPENSHIFT_REST_API_URL')
        or 'https://openshift.default.svc.cluster.local',
        config=True,
    )

    @default("openshift_rest_api_url")
    def _openshift_rest_api_url_default(self):
        return self.openshift_url

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"{self.openshift_auth_api_url}/oauth/authorize"

    @default("token_url")
    def _token_url_default(self):
        return f"{self.openshift_auth_api_url}/oauth/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"{self.openshift_rest_api_url}/apis/user.openshift.io/v1/users/~"

    def user_info_to_username(self, user_info):
        return user_info['metadata']['name']

    async def update_auth_model(self, auth_model):
        """
        Update admin status based on `admin_groups` if its configured.
        """
        if self.admin_groups:
            # if admin_groups is configured and the user wasn't part of
            # admin_users, we must set the admin status to True or False,
            # otherwise removing a user from the admin_groups won't have an
            # effect
            user_info = auth_model["auth_state"][self.user_auth_state_key]
            user_groups = set(user_info["groups"])
            auth_model["admin"] = any(user_groups & self.admin_groups)

        return auth_model

    async def check_allowed(self, username, auth_model):
        """
        Returns True for users allowed to be authorized.

        Overrides the OAuthenticator.check_allowed implementation to allow users
        either part of `allowed_users` or `allowed_groups`, and not just those
        part of `allowed_users`.
        """
        # A workaround for JupyterHub<=4.0.1, described in
        # https://github.com/jupyterhub/oauthenticator/issues/621
        if auth_model is None:
            return True

        # allow admin users recognized via admin_users or update_auth_model
        if auth_model["admin"]:
            return True

        # if allowed_users or allowed_groups is configured, we deny users not
        # part of either
        if self.allowed_users or self.allowed_groups:
            user_info = auth_model["auth_state"][self.user_auth_state_key]
            user_groups = set(user_info["groups"])
            if username in self.allowed_users:
                return True
            if any(user_groups & self.allowed_groups):
                return True
            return False

        # otherwise, authorize all users
        return True


class LocalOpenShiftOAuthenticator(LocalAuthenticator, OpenShiftOAuthenticator):

    """A version that mixes in local system user creation"""
