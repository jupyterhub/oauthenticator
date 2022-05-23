"""
Custom Authenticator to use Azure AD with JupyterHub
"""
import os
import urllib

import jwt
from jupyterhub.auth import LocalAuthenticator
from tornado.httpclient import HTTPRequest
from traitlets import Unicode, default

from .oauth2 import OAuthenticator

# For now we support both pyjwt 1 and 2, but as they have a different behavior
# we must adjust to the version. We can stop doing this if our dependency
# `mwoauth` gets a release newer than 0.3.7 that still pins pyjwt==1.*, making
# it hard for us to require pyjwt>=2.
#
# See https://github.com/mediawiki-utilities/python-mwoauth/issues/46 for a
# request for a new release to be made.
#
# To have our sphinx documentation be able to build this without installing the
# optional dependency, we have listed jwt in docs/source/conf.py's
# autodoc_mock_imports configuration. It helps, but here we call int() on the
# version that sometimes is this mocked response, and that will cause an error.
#
try:
    PYJWT_2 = int(jwt.__version__.split(".")[0]) >= 2
except Exception:
    PYJWT_2 = False


class AzureAdOAuthenticator(OAuthenticator):
    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Azure AD'),
        config=True,
        help="""Azure AD domain name string, e.g. My College""",
    )

    tenant_id = Unicode(config=True, help="The Azure Active Directory Tenant ID")

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')

    username_claim = Unicode(config=True)

    @default('username_claim')
    def _username_claim_default(self):
        return 'name'

    @default("authorize_url")
    def _authorize_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(
            self.tenant_id
        )

    @default("token_url")
    def _token_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/token'.format(
            self.tenant_id
        )

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type='authorization_code',
            code=code,
            redirect_uri=self.get_callback_url(handler),
        )

        data = urllib.parse.urlencode(params, doseq=True, encoding='utf-8', safe='=')

        url = self.token_url

        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=data,  # Body is required for a POST...
        )

        resp_json = await self.fetch(req)

        access_token = resp_json['access_token']
        id_token = resp_json['id_token']

        if PYJWT_2:
            decoded = jwt.decode(
                id_token,
                options={"verify_signature": False},
                audience=self.client_id,
            )
        else:
            # pyjwt 1.x
            decoded = jwt.decode(id_token, verify=False)

        userdict = {"name": decoded[self.username_claim]}
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        return userdict


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
