"""CILogon OAuthAuthenticator for JupyterHub

Uses OAuth 2.0 with cilogon.org (override with CILOGON_HOST)

Based on the GitHub plugin.

Most of the code c/o Kyle Kelley (@rgbkrk)

CILogon support by Adam Thornton (athornton@lsst.org)

Caveats:

- For user whitelist/admin purposes, username will be the sub claim.  This
  is unlikely to work as a Unix userid.  Typically an actual implementation
  will specify the identity provider and scopes sufficient to retrieve an
  ePPN or other unique identifier more amenable to being used as a username.
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from traitlets import Unicode, List, validate

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator

CILOGON_HOST = os.environ.get('CILOGON_HOST') or 'cilogon.org'


def _api_headers():
    return {"Accept": "application/json",
            "User-Agent": "JupyterHub",
            }


def _add_access_token(access_token, params):
    params["access_token"] = access_token


class CILogonMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/authorize" % CILOGON_HOST
    _OAUTH_TOKEN_URL = "https://%s/oauth2/token" % CILOGON_HOST


class CILogonLoginHandler(OAuthLoginHandler, CILogonMixin):
    """See http://www.cilogon.org/oidc for general information."""
    def authorize_redirect(self, *args, **kwargs):
        """Add idp, skin to redirect params"""
        extra_params = kwargs.setdefault('extra_params', {})
        if self.authenticator.idp:
            extra_params["selected_idp"] = self.authenticator.idp
        if self.authenticator.skin:
            extra_params["skin"] = self.authenticator.skin
        return super().authorize_redirect(*args, **kwargs)


class CILogonOAuthenticator(OAuthenticator):
    login_service = "CILogon"

    client_id_env = 'CILOGON_CLIENT_ID'
    client_secret_env = 'CILOGON_CLIENT_SECRET'
    login_handler = CILogonLoginHandler

    scope = List(Unicode(), default_value=['openid'],
        config=True,
        help="""The OAuth scopes to request.
        
        See cilogon_scope.md for details.
        At least 'openid' is required.
        """,
    )
    @validate('scope')
    def _validate_scope(self, proposal):
        """ensure openid is requested"""
        if 'openid' not in proposal.value:
            return ['openid'] + proposal.value
        return proposal.value
    
    idp = Unicode(
        config=True,
        help="""The `idp` attribute is the SAML Entity ID of the user's selected
            identity provider.

            See https://cilogon.org/include/idplist.xml for the list of identity
            providers supported by CILogon.
        """,
    )
    skin = Unicode(
        config=True,
        help="""The `skin` attribute is the name of the custom CILogon interface skin
            for your application.

            Contact help@cilogon.org to request a custom skin.
        """,
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        """We set up auth_state based on additional CILogon info if we
        receive it.
        """
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a CILogon Access Token
        # See: http://www.cilogon.org/oidc
        headers = _api_headers()
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.oauth_callback_url,
            code=code,
            grant_type='authorization_code',
        )

        url = url_concat("https://%s/oauth2/token" % CILOGON_HOST, params)

        req = HTTPRequest(url,
                          headers=headers,
                          method="POST",
                          body=''
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        access_token = resp_json['access_token']
        self.log.info("Access token acquired.")
        # Determine who the logged in user is
        params = dict(access_token=access_token)
        req = HTTPRequest(url_concat("https://%s/oauth2/userinfo" %
                                     CILOGON_HOST, params),
                          headers=headers
                          )
        self.log.info("REQ: %s / %r" % (str(req), req))
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        self.log.info(json.dumps(resp_json, sort_keys=True, indent=4))

        if "sub" not in resp_json or not resp_json["sub"]:
            return None
        username = resp_json["sub"]
        # username is now the CILogon "sub" claim.  This is not ideal.
        userdict = {"name": username}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        # Save the access token and full CILogon reply in auth state
        # These can be used for user provisioning
        #  in the Lab/Notebook environment.
        auth_state['access_token'] = access_token
        # store the whole user model in auth_state.cilogon_user
        auth_state['cilogon_user'] = resp_json
        return userdict


class LocalGitHubOAuthenticator(LocalAuthenticator, CILogonOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
