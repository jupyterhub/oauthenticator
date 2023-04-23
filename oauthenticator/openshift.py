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

    async def user_is_authorized(self, auth_model):
        """
        Use the group info stored on the OpenShift User object to determine if a user
        is authorized to login.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]

        username = auth_model["name"]
        if username in (self.allowed_users | self.admin_users):
            return True

        user_groups = set(user_info["groups"])
        return any(user_groups & (self.allowed_groups | self.admin_groups))

    async def update_auth_model(self, auth_model):
        """
        Set the admin status based on finding the username in `admin_users` or
        finding a user group part of `admin_groups`.
        """
        user_info = auth_model["auth_state"][self.user_auth_state_key]

        username = auth_model["name"]
        if username in self.admin_users:
            auth_model["admin"] = True
            return auth_model

        if self.admin_groups:
            # admin_groups are declared and the user wasn't part of admin_users,
            # so we set admin to True or False to allow a user removed from an
            # admin_groups to no longer be an admin.
            user_groups = set(user_info["groups"])
            auth_model["admin"] = any(user_groups & self.admin_groups)

        return auth_model


class LocalOpenShiftOAuthenticator(LocalAuthenticator, OpenShiftOAuthenticator):

    """A version that mixes in local system user creation"""
