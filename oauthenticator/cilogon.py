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

from jupyterhub.auth import LocalAuthenticator
from tornado import web
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import Bool, Dict, List, Unicode, default, validate

from .oauth2 import OAuthenticator, OAuthLoginHandler


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
        "idp_whitelist": ("allowed_domains", "0.12.0"),
        "allowed_idps": ("allowed_domains", "15.0.0"),
        "idp": ("shown_idps", "15.0.0"),
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
        allowed_auth_providers is specified"""
        if self.allowed_auth_providers and 'org.cilogon.userinfo' not in proposal.value:
            scopes += ['org.cilogon.userinfo']

        return scopes

    idp_whitelist = List(
        help="Deprecated, use `CIlogonOAuthenticator.allowed_domains`",
        config=True,
    )

    allowed_idps = Dict(
        Unicode(),
        config=True,
        help="""A dictionary of the only entity IDs that will be allowed to use on login.
        See https://cilogon.org/idplist for the list of `EntityIDs` of each IDP.

        The entity ids can have a username-derivation scheme that can be used to override
        the `CILogonOAuthenticator.strip_idp_domain`, `CILogonOAuthenticator.username_claim`
        options on a per-idp basis to avoid username clashes.

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
        will be stripped, but if you login with github, it'll be your GitHub username prefixed with gh:.
        This way, multiple users can log in without clashes across IDPs

        If no `username-derivation dict` is provided, then `CILogonOAuthenticator.strip_idp_domain`
        and `CILogonOAuthenticator.username_claim` will be used for every idp-id in `allowed_idps`.

        Warning: if there are more than one idp in this dict and no username-derivation specified,
        then username clashes might happen!
        """,
    )

    def _valid_username_derivation_config(self):
        """
        Checks whether or not the username_derivation config is valid and only contains accepted
        keys and values.
        """

        username_derivation_dict = self.allowed_idps["username-derivation"]
        allowed_username_derivation_keys = ["username_claim", "action", "domain", "prefix"]
        for key, value in username_derivation_dict.items():
            if key not in allowed_username_derivation_keys:
                self.log.error(
                    f"Config username-derivation.{key} not recognized! Available options are: {allowed_username_derivation_keys}",
                )
                return False

            # Make sure only supported actions are passed
            allowed_actions = ["strip-idp-domain", "prefix"]
            if key == "action":
                if value not in allowed_actions:
                    self.log.error(
                        f"Config {key}.{value} not recognized! Available options are: {key}.{allowed_actions}",
                    )
                    return False

                # When action is strip-idp-domain, domain to strip must be passed
                if value == "strip-idp-domain":
                    if not self.allowed_idps["username-derivation"].get("domain", None):
                        return False
                # When action is prefix, prefix to add must be passed
                if value == "prefix":
                    if not self.allowed_idps["username-derivation"].get("prefix", None):
                        return False

        return True


    @validate("allowed_idps")
    def _validate_allowed_idps(self, proposal):
        idps = proposal.value
        valid_idps_dict = {}

        for entity_id, username_derivation in idps.items():

            # Make sure allowed_auth_providers containes EntityIDs and not domain names.
            if "https://" not in entity_id:
                # Validate entity ids are the form of: `https://github.com/login/oauth/authorize`
                self.log.error(
                    f"Trying to allow an auth provider that doesn't look like a valid CILogon EntityIDs {entity_id}",
                )
                raise ValueError(
                    """The keys of `allowed_idps` **must** be CILogon permitted EntityIDs.
                    See https://cilogon.org/idplist for the list of EntityIDs of each IDP.
                    """
                )

            # No username-derivation config passed, skip validation
            if not username_derivation:
                continue

            # Validate it's username_derivation what we're configuring for each idp id and not something else
            if len(username_derivation.keys()) > 1:
                valid_idps_dict[entity_id] = {}

            if not username_derivation.get("username-derivation", None):
                self.log.error(
                    f"Config not recognized! Available option is {entity_id}.username-derivation.",
                )
                valid_idps_dict[entity_id] = {}
                continue

            # Validate username-derivation dict config is valid
            if not self._valid_username_derivation_config():
                valid_idps_dict[entity_id] = {}
                continue

        # If valid_idps is not empty, it means some part of the config wasn't valid and we've overwritten it
        if valid_idps_dict:
            return valid_idps_dict

        return idps


    strip_idp_domain = Bool(
        False,
        config=True,
        help="""Remove the IDP domain from the username. Note that this option can be overwritten
        by allowed_idps[username-derivation] config if present.
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

        if self.allowed_auth_providers:
            selected_auth_provider = resp_json.get("idp")
            if selected_auth_provider not in self.allowed_auth_providers:
                self.log.error(
                    "Trying to login from an identity provider that wasn't allowed %s",
                    selected_auth_provider,
                )
                raise web.HTTPError(
                    500, "Trying to login using an identity provider not allowed"
                )

            if self.allowed_domains:
                gotten_name, gotten_idp = username.split('@')
                if gotten_idp not in self.allowed_domains:
                    self.log.error(
                        "Trying to login from not allowed domain %s", gotten_idp
                    )
                    raise web.HTTPError(
                        500, "Trying to login from a domain not allowed"
                    )
                if len(self.allowed_domains) == 1 and self.strip_idp_domain:
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
