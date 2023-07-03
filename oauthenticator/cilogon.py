"""
A JupyterHub authenticator class for use with CILogon as an identity provider.
"""
import os
from urllib.parse import urlparse

import jsonschema
from jupyterhub.auth import LocalAuthenticator
from ruamel.yaml import YAML
from tornado import web
from traitlets import Bool, Dict, List, Unicode, default, validate

from .oauth2 import OAuthenticator, OAuthLoginHandler

yaml = YAML(typ="safe", pure=True)


class CILogonLoginHandler(OAuthLoginHandler):
    """See https://www.cilogon.org/oidc for general information."""

    def authorize_redirect(self, *args, **kwargs):
        """
        Optionally add "skin" to redirect params, and always add "selected_idp"
        (aka. "idphint") based on allowed_idps config.

        Related documentation at https://www.cilogon.org/oidc#h.p_IWGvXH0okDI_.
        """
        # kwargs is updated to include extra_params if it doesn't already
        # include it, we then modify kwargs' extra_params dictionary
        extra_params = kwargs.setdefault('extra_params', {})

        # selected_idp should be a comma separated string
        allowed_idps = ",".join(self.authenticator.allowed_idps.keys())
        extra_params["selected_idp"] = allowed_idps

        if self.authenticator.skin:
            extra_params["skin"] = self.authenticator.skin

        return super().authorize_redirect(*args, **kwargs)


class CILogonOAuthenticator(OAuthenticator):
    login_handler = CILogonLoginHandler

    user_auth_state_key = "cilogon_user"
    client_id_env = 'CILOGON_CLIENT_ID'
    client_secret_env = 'CILOGON_CLIENT_SECRET'

    @default("login_service")
    def _login_service_default(self):
        return os.environ.get("LOGIN_SERVICE", "CILogon")

    cilogon_host = Unicode(
        os.environ.get("CILOGON_HOST") or "cilogon.org",
        config=True,
        help="""
        Used to determine the default values for `authorize_url`, `token_url`,
        and `userdata_url`.
        """,
    )

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"https://{self.cilogon_host}/authorize"

    @default("token_url")
    def _token_url(self):
        return f"https://{self.cilogon_host}/oauth2/token"

    @default("userdata_url")
    def _userdata_url_default(self):
        return f"https://{self.cilogon_host}/oauth2/userinfo"

    scope = List(
        Unicode(),
        default_value=['openid', 'email', 'org.cilogon.userinfo', 'profile'],
        config=True,
        help="""
        OAuth scopes to request.

        `openid` and `org.cilogon.userinfo` is required.

        Read more about CILogon scopes in https://www.cilogon.org/oidc.
        """,
    )

    @validate('scope')
    def _validate_scope(self, proposal):
        """
        Ensure `openid` and `org.cilogon.userinfo` is requested.

        - The `idp` claim is required, and its documented to associate with
          requesting the `org.cilogon.userinfo` scope.

        ref: https://www.cilogon.org/oidc#h.p_PEQXL8QUjsQm
        """
        scopes = proposal.value

        if 'openid' not in proposal.value:
            scopes += ['openid']

        if 'org.cilogon.userinfo' not in proposal.value:
            scopes += ['org.cilogon.userinfo']

        return scopes

    allowed_idps = Dict(
        config=True,
        help="""
        A dictionary of the only entity IDs that will be allowed to be used as
        login options. See https://cilogon.org/idplist for the list of
        `EntityIDs` of each IdP.

        It can be used to enable domain stripping, adding prefixes to the
        usernames and to specify an identity provider specific username claim.

        For example::

            c.CILogonOAuthenticator.allowed_idps = {
                "https://idpz.utorauth.utoronto.ca/shibboleth": {
                    "username_derivation": {
                        "username_claim": "email",
                        "action": "strip_idp_domain",
                        "domain": "utoronto.ca",
                    },
                },
                "https://github.com/login/oauth/authorize": {
                    "username_derivation": {
                        "username_claim": "username",
                        "action": "prefix",
                        "prefix": "github",
                    },
                },
                "http://google.com/accounts/o8/id": {
                    "username_derivation": {
                        "username_claim": "username",
                        "action": "prefix",
                        "prefix": "google",
                    },
                    "allowed_domains": ["uni.edu", "something.org"],
                },
            }

        Where `username_derivation` defines:

            * `username_claim`: string (required)
                The claim in the `userinfo` response from which to get the
                JupyterHub username. Examples include: `eppn`, `email`. What
                keys are available will depend on the scopes requested.
            * `action`: string
                What action to perform on the username. Available options are
                "strip_idp_domain", which will strip the domain from the
                username if specified and "prefix", which will prefix the hub
                username with "prefix:".
            * `domain:` string (required if action is strip_idp_domain)
                The domain after "@" which will be stripped from the username if
                it exists and if the action is "strip_idp_domain".
            * `prefix`: string (required if action is prefix)
                The prefix which will be added at the beginning of the username
                followed by a semi-column ":", if the action is "prefix".
            * `allowed_domains`: string
                It defines which domains will be allowed to login using the
                specific identity provider.

        .. versionchanged:: 15.0

           Changed format from a list to a dictionary.
        """,
    )

    @validate("allowed_idps")
    def _validate_allowed_idps(self, proposal):
        idps = proposal.value

        if not idps:
            raise ValueError("One or more allowed_idps must be configured")

        for entity_id, idp_config in idps.items():
            # Validate `idp_config` config using the schema
            root_dir = os.path.dirname(os.path.abspath(__file__))
            schema_file = os.path.join(root_dir, "schemas", "cilogon-schema.yaml")
            with open(schema_file) as schema_fd:
                schema = yaml.load(schema_fd)
                # Raises useful exception if validation fails
                jsonschema.validate(idp_config, schema)

            # Make sure allowed_idps contains EntityIDs and not domain names.
            accepted_entity_id_scheme = ["urn", "https", "http"]
            entity_id_scheme = urlparse(entity_id).scheme
            if entity_id_scheme not in accepted_entity_id_scheme:
                # Validate entity ids are the form of: `https://github.com/login/oauth/authorize`
                self.log.error(
                    f"Trying to allow an auth provider: {entity_id}, that doesn't look like a valid CILogon EntityID.",
                )
                raise ValueError(
                    "The keys of `allowed_idps` **must** be CILogon permitted EntityIDs. "
                    "See https://cilogon.org/idplist for the list of EntityIDs of each IDP."
                )

        return idps

    skin = Unicode(
        config=True,
        help="""
        The `skin` attribute is the name of the custom CILogon interface skin
        for your application.

        Contact help@cilogon.org to request a custom skin.
        """,
    )

    # _deprecated_oauth_aliases is used by deprecation logic in OAuthenticator
    _deprecated_oauth_aliases = {
        "idp_whitelist": ("allowed_idps", "0.12.0", False),
        "idp": ("shown_idps", "15.0.0", False),
        "strip_idp_domain": ("allowed_idps", "15.0.0", False),
        "shown_idps": ("allowed_idps", "16.0.0", False),
        "additional_username_claims": ("allowed_idps", "16.0.0", False),
        "username_claim": ("allowed_idps", "16.0.0", False),
        **OAuthenticator._deprecated_oauth_aliases,
    }
    idp_whitelist = List(
        config=True,
        help="""
        .. versionremoved:: 0.12

           Use :attr:`allowed_idps`.
        """,
    )
    idp = Unicode(
        config=True,
        help="""
        .. versionremoved:: 15.0

           Use :attr:`allowed_idps`.
        """,
    )
    strip_idp_domain = Bool(
        config=True,
        help="""
        .. versionremoved:: 15.0

           Use :attr:`allowed_idps`.
        """,
    )
    shown_idps = List(
        config=True,
        help="""
        .. versionremoved:: 16.0

           Use :attr:`allowed_idps`.
        """,
    )
    additional_username_claims = List(
        config=True,
        help="""
        .. versionremoved:: 16.0

           Use :attr:`allowed_idps`.
        """,
    )
    username_claim = Unicode(
        config=True,
        help="""
        .. versionremoved:: 16.0

           Use :attr:`allowed_idps`.
        """,
    )

    def user_info_to_username(self, user_info):
        """
        Overrides OAuthenticator.user_info_to_username that relies on
        username_claim to instead consider idp specific config in under
        allowed_idps[user_info["idp"]]["username_derivation"].

        Returns a username based on user_info and configuration in allowed_idps
        under the associated idp's username_derivation config.
        """
        # NOTE: The first time we have received user_info is when
        #       user_info_to_username is called by OAuthenticator.authenticate,
        #       so we make a check here that the "idp" claim is received and
        #       that we allowed_idps is configured to handle that idp.
        #
        user_idp = user_info.get("idp")
        if not user_idp:
            message = "'idp' claim was not part of the response to the userdata_url"
            self.log.error(message)
            raise web.HTTPError(500, message)
        if not self.allowed_idps.get(user_idp):
            message = f"Login with identity provider {user_idp} is not pre-configured"
            self.log.error(message)
            raise web.HTTPError(403, message)

        unprocessed_username = self._user_info_to_unprocessed_username(user_info)
        username = self._get_processed_username(unprocessed_username, user_info)

        return username

    def _user_info_to_unprocessed_username(self, user_info):
        """
        Returns a username from user_info without also applying the "action"
        specified under "username_derivation" for the associated idp.
        """
        user_idp = user_info["idp"]
        username_derivation = self.allowed_idps[user_idp]["username_derivation"]
        username_claim = username_derivation["username_claim"]

        username = user_info.get(username_claim)
        if not username:
            message = f"Configured username_claim {username_claim} for {user_idp} was not found in the response {user_info.keys()}"
            self.log.error(message)
            raise web.HTTPError(500, message)

        return username

    def _get_processed_username(self, username, user_info):
        """
        Optionally adjusts a username from user_info based on the "action"
        specified under "username_derivation" for the associated idp.
        """
        user_idp = user_info["idp"]
        username_derivation = self.allowed_idps[user_idp]["username_derivation"]

        # Optionally execute action "strip_idp_domain" or "prefix"
        action = username_derivation.get("action")
        if action == "strip_idp_domain":
            domain_suffix = "@" + username_derivation["domain"]
            if username.lower().endswith(domain_suffix.lower()):
                username = username[: -len(domain_suffix)]
        elif action == "prefix":
            prefix = username_derivation["prefix"]
            username = f"{prefix}:{username}"

        return username

    async def check_allowed(self, username, auth_model):
        """
        Overrides the OAuthenticator.check_allowed to also allow users part of
        an `allowed_domains` as configured under `allowed_idps`.
        """
        if await super().check_allowed(username, auth_model):
            return True

        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_idp = user_info["idp"]
        idp_allowed_domains = self.allowed_idps[user_idp].get("allowed_domains")
        if idp_allowed_domains:
            unprocessed_username = self._user_info_to_unprocessed_username(user_info)
            user_domain = unprocessed_username.split("@", 1)[1].lower()
            if user_domain in idp_allowed_domains:
                return True

            message = f"Login with domain @{user_domain} is not allowed"
            self.log.warning(message)
            raise web.HTTPError(403, message)

        # users should be explicitly allowed via config, otherwise they aren't
        return False


class LocalCILogonOAuthenticator(LocalAuthenticator, CILogonOAuthenticator):
    """A version that mixes in local system user creation"""
