"""
A JupyterHub authenticator class for use with CILogon as an identity provider.
"""

import os
from fnmatch import fnmatch
from urllib.parse import urlparse

import jsonschema
from jupyterhub.auth import LocalAuthenticator
from ruamel.yaml import YAML
from tornado import web
from traitlets import Bool, Dict, List, Unicode, default, validate

from .oauth2 import OAuthenticator, OAuthLoginHandler

yaml = YAML(typ="safe", pure=True)


def _get_select_idp_param(allowed_idps):
    """
    The "selected_idp" query parameter included when the user is redirected to
    CILogon should be a comma separated string of idps to choose from, where the
    first entry is pre-selected as the default choice. The ordering of the
    remaining idps has no meaning.
    """
    # pick the first idp marked as default, or fallback to the first idp
    default_keys = [k for k, v in allowed_idps.items() if v.get("default")]
    default_key = next(iter(default_keys), next(iter(allowed_idps)))

    # put the default idp first followed by the other idps
    other_keys = [k for k, _ in allowed_idps.items() if k != default_key]
    selected_idp = ",".join([default_key] + other_keys)

    return selected_idp


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

        extra_params["selected_idp"] = _get_select_idp_param(
            self.authenticator.allowed_idps
        )
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
                    "allow_all": True,
                    "default": True,
                },
                "http://google.com/accounts/o8/id": {
                    "username_derivation": {
                        "username_claim": "email",
                        "action": "prefix",
                        "prefix": "google",
                    },
                    "allowed_domains": ["uni.edu", "something.org"],
                },
                "https://github.com/login/oauth/authorize": {
                    "username_derivation": {
                        "username_claim": "preferred_username",
                        "action": "prefix",
                        "prefix": "github",
                    },
                    # allow_all or allowed_domains not specified for ths idp,
                    # this means that its users must be explicitly allowed
                    # with a config such as allowed_users or admin_users.
                },
            }
            c.Authenticator.admin_users = ["github-user1"]
            c.Authenticator.allowed_users = ["github-user2"]

        This is a description of the configuration you can pass to
        `allowed_idps`.

        * `default`: bool (optional)
            Determines the identity provider to be pre-selected in a list for
            users arriving to CILogons login screen.
        * `username_derivation`: string (required)
            * `username_claim`: string (required)
                The claim in the `userinfo` response from which to define the
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
        * `allow_all`: bool (defaults to False)
            Configuring this allows all users authenticating with this identity
            provider.
        * `allowed_domains`: list of strings
            Allows users associated with a listed domain to sign in.

            Use of wildcards `*` and a bit more is supported via Python's
            `fnmatch` function since version 16.2. Setting `allowed_domains` to
            `["jupyter.org", "*.jupyter.org"]` would for example allow users
            with `jovyan@jupyter.org` or `jovyan@hub.jupyter.org` usernames.

            The domain the user is associated with is based on the username by
            default in version 16, but this can be reconfigured to be based on a
            claim in the `userinfo` response via `allowed_domains_claim`. The
            domain is treated case insensitive and can either be directly
            specified by the claim's value or extracted from an email string.
        * `allowed_domains_claim`: string (optional)
            This configuration represents the claim in the `userinfo` response
            to identify a domain that could allow a user to sign in via
            `allowed_domains`.

            The claim can defaults to the username claim in version 16, but this
            will change to "email" in version 17.

            .. versionadded:: 16.2

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

            # Make allowed_domains lowercase
            idp_config["allowed_domains"] = [
                ad.lower() for ad in idp_config.get("allowed_domains", [])
            ]

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
        Overrides the OAuthenticator.check_allowed to also allow users based on
        idp specific config `allow_all` and `allowed_domains` as configured
        under `allowed_idps`.
        """
        if await super().check_allowed(username, auth_model):
            return True

        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_idp = user_info["idp"]

        idp_allow_all = self.allowed_idps[user_idp].get("allow_all")
        if idp_allow_all:
            return True

        idp_allowed_domains = self.allowed_idps[user_idp].get("allowed_domains")
        if idp_allowed_domains:
            idp_allowed_domains_claim = self.allowed_idps[user_idp].get(
                "allowed_domains_claim"
            )
            if idp_allowed_domains_claim:
                raw_user_domain = user_info.get(idp_allowed_domains_claim)
                if not raw_user_domain:
                    message = f"Configured allowed_domains_claim {idp_allowed_domains_claim} for {user_idp} was not found in the response {user_info.keys()}"
                    self.log.error(message)
                    raise web.HTTPError(500, message)
            else:
                raw_user_domain = self._user_info_to_unprocessed_username(user_info)

            # refine a domain from a string that possibly looks like an email
            user_domain = raw_user_domain.split("@")[-1].lower()

            for ad in idp_allowed_domains:
                # fnmatch allow us to use wildcards like * and ?, but
                # not the full regex. For simple domain matching this is
                # good enough. If we were to use regexes instead, people
                # will have to escape all their '.'s, and since that is
                # actually going to match 'any character' it is a
                # possible security hole. For details see
                # https://docs.python.org/3/library/fnmatch.html.
                if fnmatch(user_domain, ad):
                    return True

        # users should be explicitly allowed via config, otherwise they aren't
        return False


class LocalCILogonOAuthenticator(LocalAuthenticator, CILogonOAuthenticator):
    """A version that mixes in local system user creation"""
