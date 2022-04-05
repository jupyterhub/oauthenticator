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
import os
from urllib.parse import urlparse

import jsonschema
from jupyterhub.auth import LocalAuthenticator
from ruamel.yaml import YAML
from tornado import web
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import Bool, Dict, List, Unicode, default, validate

from .oauth2 import OAuthenticator, OAuthLoginHandler

yaml = YAML(typ="safe", pure=True)


class CILogonLoginHandler(OAuthLoginHandler):
    """See http://www.cilogon.org/oidc for general information."""

    def authorize_redirect(self, *args, **kwargs):
        """Add idp, skin to redirect params"""
        extra_params = kwargs.setdefault('extra_params', {})
        if self.authenticator.shown_idps:
            extra_params["selected_idp"] = self.authenticator.shown_idps
        if self.authenticator.skin:
            extra_params["skin"] = self.authenticator.skin

        return super().authorize_redirect(*args, **kwargs)


class CILogonOAuthenticator(OAuthenticator):
    _deprecated_oauth_aliases = {
        "idp_whitelist": ("allowed_idps", "0.12.0", False),
        "idp": ("shown_idps", "15.0.0", False),
        "strip_idp_domain": ("allowed_idps", "15.0.0", False),
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
        scopes = proposal.value

        """ensure openid is requested"""
        if 'openid' not in proposal.value:
            scopes += ['openid']

        """ ensure org.cilogon.userinfo is requested when
        allowed_idps is specified"""
        if self.allowed_idps and 'org.cilogon.userinfo' not in proposal.value:
            scopes += ['org.cilogon.userinfo']

        return scopes

    idp_whitelist = List(
        help="Deprecated, use `CIlogonOAuthenticator.allowed_domains`",
        config=True,
    )

    allowed_idps = Dict(
        config=True,
        default_value={},
        help="""A dictionary of the only entity IDs that will be allowed to use on login.
        See https://cilogon.org/idplist for the list of `EntityIDs` of each IDP.

        The entity ids can have a username-derivation scheme that can be used to enable
        stripping idp domains from hub usernames and overwrite the option
        `CILogonOAuthenticator.username_claim` on a per-idp basis to avoid username clashes.

        Required format:
            - `username-derivation` dict can only contain the following keys:
              ["username-claim", "action", "domain", "prefix"].
            - `username-derivation.action` can only be `strip-idp-domain` or `prefix`
            - if `username-derivation.action` is `strip-idp-domain`, then
              `username-derivation.domain` must be specified
            - if `username-derivation.action` is `prefix`, then `username-derivation.prefix`
              must be specified.

        For example:
        {
            "idp-id-for-uni-edu": {
                "username-derivation": {
                    "username-claim": "email",
                    "action": "strip-idp-domain",
                    "domain": "berkeley.edu",
                }
            },
            "idp-id-for-github": {
                "username-derivation": {
                    "username-claim": "username",
                    "action": "prefix",
                    "prefix": "gh"
                }
            }
        }

        If you login with a `uni.edu` account, the hub username will be your email, from which the domain
        will be stripped, but if you login with github, it'll be your GitHub username prefixed with `gh:`.
        This way, multiple users can log in without clashes across IDPs

        Note: if no `username-derivation dict` is provided, then no domain stripping will take place!
        Also, `CILogonOAuthenticator.username_claim` will be used for the hub username, for every idp
        id in `allowed_idps`.
        """,
    )

    @validate("allowed_idps")
    def _validate_allowed_idps(self, proposal):
        idps = proposal.value

        for entity_id, username_derivation in idps.items():
            accepted_entity_id_scheme = ["urn", "https", "http"]
            entity_id_scheme = urlparse(entity_id).scheme
            # Make sure allowed_idps containes EntityIDs and not domain names.
            if entity_id_scheme not in accepted_entity_id_scheme:
                # Validate entity ids are the form of: `https://github.com/login/oauth/authorize`
                self.log.error(
                    f"Trying to allow an auth provider: {entity_id}, that doesn't look like a valid CILogon EntityID.",
                )
                raise ValueError(
                    """The keys of `allowed_idps` **must** be CILogon permitted EntityIDs.
                    See https://cilogon.org/idplist for the list of EntityIDs of each IDP.
                    """
                )
            root_dir = os.path.dirname(os.path.abspath(__file__))
            schema_file = os.path.join(root_dir, "schemas", "cilogon-schema.yaml")
            with open(schema_file) as schema_fd:
                schema = yaml.load(schema_fd)
                # Raises useful exception if validation fails
                jsonschema.validate(username_derivation, schema)

        return idps

    strip_idp_domain = Bool(
        False,
        config=True,
        help="""Deprecated, use CIlogonOAuthenticator.allowed_idps["username-derivation"]["action"] = "strip-idp-domain"
        to enable it and CIlogonOAuthenticator.allowed_idps["username-derivation"]["domain"] to list the domain
        which will be stripped
        """,
    )

    shown_idps = List(
        Unicode(),
        config=True,
        help="""A list of idps to be shown as login options.
        The `idp` attribute is the SAML Entity ID of the user's selected
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

        Note that this option can be overwritten by allowed_idps[username-derivation]
        config if present.
        """,
    )

    additional_username_claims = List(
        config=True,
        help="""Additional claims to check if the username_claim fails.

        This is useful for linked identities where not all of them return
        the primary username_claim.
        """,
    )

    def check_username_claim(self, claimlist, resp_json):
        for claim in claimlist:
            username = resp_json.get(claim)
            if username:
                return username

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

    async def authenticate(self, handler, data=None):
        """We set up auth_state based on additional CILogon info if we
        receive it.
        """
        code = handler.get_argument("code")

        # Exchange the OAuth code for a CILogon Access Token
        # See: http://www.cilogon.org/oidc
        headers = {"Accept": "application/json", "User-Agent": "JupyterHub"}

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
        )

        url = url_concat(self.token_url, params)

        req = HTTPRequest(url, headers=headers, method="POST", body='')

        token_response = await self.fetch(req)
        access_token = token_response['access_token']
        # Determine who the logged in user is
        params = dict(access_token=access_token)
        req = HTTPRequest(
            url_concat("https://%s/oauth2/userinfo" % self.cilogon_host, params),
            headers=headers,
        )
        resp_json = await self.fetch(req)

        claimlist = [self.username_claim]
        if self.additional_username_claims:
            claimlist.extend(self.additional_username_claims)

        selected_auth_provider = resp_json.get("idp")
        # Check if selected idp was marked as allowed
        if self.allowed_idps:
            # Faild hard if idp wasn't allowed
            if selected_auth_provider not in self.allowed_idps.keys():
                self.log.error(
                    "Trying to login from an identity provider that wasn't allowed %s",
                    selected_auth_provider,
                )
                raise web.HTTPError(
                    500, "Trying to login using an identity provider not allowed"
                )

            # Check if another username_claim should be used for this idp
            if (
                self.allowed_idps[selected_auth_provider]
                .get("username-derivation", {})
                .get("username-claim", None)
            ):
                claimlist = [
                    self.allowed_idps[selected_auth_provider]["username-derivation"][
                        "username-claim"
                    ]
                ]

        # Check if the requested username_claim exists in the response from the provider
        username = self.check_username_claim(claimlist, resp_json)

        # Check if we need to strip/prefix username
        if self.allowed_idps:
            username_derivation_config = self.allowed_idps.get(
                selected_auth_provider, None
            ).get("username-derivation", {})
            if username_derivation_config:
                action = username_derivation_config["action"]
                if action == "strip-idp-domain":
                    gotten_name, gotten_domain = username.split('@')
                    if gotten_domain != username_derivation_config["domain"]:
                        self.log.warning(
                            """Trying to strip from the username a domain that doesn't exist.
                            Username will be left unchanged.
                            """
                        )
                    else:
                        username = gotten_name
                elif action == "prefix":
                    prefix = username_derivation_config["prefix"]
                    username = f"{prefix}:{username}"

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
