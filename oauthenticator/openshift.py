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
        auth_info_url = '%s/.well-known/oauth-authorization-server' % self.openshift_url

        resp = requests.get(auth_info_url, verify=self.ca_certs or self.validate_cert)
        resp_json = resp.json()

        return resp_json.get('issuer')

    openshift_rest_api_url = Unicode(
        os.environ.get('OPENSHIFT_REST_API_URL')
        or 'https://openshift.default.svc.cluster.local',
        config=True,
    )

    @default("user_auth_state_key")
    def _user_auth_state_key_default(self):
        return "openshift_user"

    @default("openshift_rest_api_url")
    def _openshift_rest_api_url_default(self):
        return self.openshift_url

    @default("authorize_url")
    def _authorize_url_default(self):
        return "%s/oauth/authorize" % self.openshift_auth_api_url

    @default("token_url")
    def _token_url_default(self):
        return "%s/oauth/token" % self.openshift_auth_api_url

    @default("username_claim")
    def _username_claim_default(self):
        return "name"

    @default("userdata_url")
    def _userdata_url_default(self):
        return "%s/apis/user.openshift.io/v1/users/~" % self.openshift_rest_api_url

    @staticmethod
    def user_in_groups(user_groups: set, allowed_groups: set):
        return any(user_groups.intersection(allowed_groups))

    def user_info_to_username(self, user_info):
        return user_info['metadata']['name']

    async def update_auth_model(self, auth_model):
        """
        Use the group info stored on the OpenShift User object to determine if a user
        is an admin and update the auth_model with this info.
        """
        user_groups = set(auth_model['auth_state']['openshift_user']['groups'])

        if self.admin_groups:
            auth_model['admin'] = self.user_in_groups(user_groups, self.admin_groups)

        return auth_model

    async def user_is_authorized(self, auth_model):
        """
        Use the group info stored on the OpenShift User object to determine if a user
        is authorized to login.
        """
        user_groups = set(auth_model['auth_state']['openshift_user']['groups'])
        username = auth_model['name']

        if self.allowed_groups or self.admin_groups:
            msg = f"username:{username} User not in any of the allowed/admin groups"
            if not self.user_in_groups(user_groups, self.allowed_groups):
                if not self.user_in_groups(user_groups, self.admin_groups):
                    self.log.warning(msg)
                    return False

        return True


class LocalOpenShiftOAuthenticator(LocalAuthenticator, OpenShiftOAuthenticator):

    """A version that mixes in local system user creation"""

    pass
