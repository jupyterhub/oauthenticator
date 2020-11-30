"""CILogon OAuthAuthenticator for JupyterHub

Uses OAuth 2.0 with cilogon.org (override with CILOGON_HOST)

Caveats:

- For allowed user list /admin purposes, username will be the ePPN by default.
  This is typically an email address and may not work as a Unix userid.
  Normalization may be required to turn the JupyterHub username into a Unix username.
- Default username_claim of ePPN does not work for all providers,
  e.g. generic OAuth such as Google.
  Use `c.CILogonOAuthenticator.username_claim = 'email'` to use
  email instead of ePPN as the JupyterHub username.
"""

import json
import os

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from traitlets import Unicode, List, Bool, default, validate, observe

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator


class CILogonLoginHandler(OAuthLoginHandler):
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
    _deprecated_oauth_aliases = {
        "idp_whitelist": ("allowed_idps", "0.12.0"),
        **OAuthenticator._deprecated_oauth_aliases,
    }

    login_service = "CILogon"

    client_id_env = 'CILOGON_CLIENT_ID'
    client_secret_env = 'CILOGON_CLIENT_SECRET'
    login_handler = CILogonLoginHandler

    cilogon_host = Unicode(os.environ.get("CILOGON_HOST") or "cilogon.org", config=True)

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://%s/authorize" % self.cilogon_host

    @default("token_url")
    def _token_url(self):
        return "https://%s/oauth2/token" % self.cilogon_host

    scope = List(
        Unicode(),
        default_value=['openid', 'email', 'org.cilogon.userinfo'],
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

    idp_whitelist = List(help="Deprecated, use `CIlogonOAuthenticator.allowed_idps`", config=True,)
    allowed_idps = List(
        config=True,
        help="""A list of IDP which can be stripped from the username after the @ sign.""",
    )
    strip_idp_domain = Bool(
        False,
        config=True,
        help="""Remove the IDP domain from the username. Note that only domains which
             appear in the `allowed_idps` will be stripped.""",
    )
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
    username_claim = Unicode(
        "eppn",
        config=True,
        help="""The claim in the userinfo response from which to get the JupyterHub username

            Examples include: eppn, email

            What keys are available will depend on the scopes requested.

            See http://www.cilogon.org/oidc for details.
        """,
    )

    additional_username_claims = List(
        config=True,
        help="""Additional claims to check if the username_claim fails.

        This is useful for linked identities where not all of them return
        the primary username_claim.
        """,
    )

    async def authenticate(self, handler, data=None):
        """We set up auth_state based on additional CILogon info if we
        receive it.
        """
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a CILogon Access Token
        # See: http://www.cilogon.org/oidc
        headers = {"Accept": "application/json", "User-Agent": "JupyterHub"}

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.oauth_callback_url,
            code=code,
            grant_type='authorization_code',
        )

        url = url_concat(self.token_url, params)

        req = HTTPRequest(url, headers=headers, method="POST", body='')

        resp = await http_client.fetch(req)
        token_response = json.loads(resp.body.decode('utf8', 'replace'))
        access_token = token_response['access_token']
        self.log.info("Access token acquired.")
        # Determine who the logged in user is
        params = dict(access_token=access_token)
        req = HTTPRequest(
            url_concat("https://%s/oauth2/userinfo" % self.cilogon_host, params),
            headers=headers,
        )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        claimlist = [self.username_claim]
        if self.additional_username_claims:
            claimlist.extend(self.additional_username_claims)

        for claim in claimlist:
            username = resp_json.get(claim)
            if username:
                break
        if not username:
            if len(claimlist) < 2:
                self.log.error(
                    "Username claim %s not found in response: %s",
                    self.username_claim,
                    sorted(resp_json.keys()),
                )
            else:
                self.log.error(
                    "No username claim from %r in response: %s",
                    claimlist,
                    sorted(resp_json.keys()),
                )
            raise web.HTTPError(500, "Failed to get username from CILogon")

        if self.allowed_idps:
            gotten_name, gotten_idp = username.split('@')
            if gotten_idp not in self.allowed_idps:
                self.log.error(
                    "Trying to login from not allowed domain %s", gotten_idp
                )
                raise web.HTTPError(500, "Trying to login from a domain not allowed")
            if len(self.allowed_idps) == 1 and self.strip_idp_domain:
                username = gotten_name
        userdict = {"name": username}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        # Save the token response and full CILogon reply in auth state
        # These can be used for user provisioning
        #  in the Lab/Notebook environment.
        auth_state['token_response'] = token_response
        # store the whole user model in auth_state.cilogon_user
        # keep access_token as well, in case anyone was relying on it
        auth_state['access_token'] = access_token
        auth_state['cilogon_user'] = resp_json
        return userdict


class LocalCILogonOAuthenticator(LocalAuthenticator, CILogonOAuthenticator):

    """A version that mixes in local system user creation"""

    pass
