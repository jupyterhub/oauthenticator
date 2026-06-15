import inspect
import os
import time
from functools import wraps

from jupyterhub.auth import LocalAuthenticator
from traitlets import Unicode, default

from .oauth2 import OAuthenticator, OAuthLoginHandler


class OIDCLoginHandler(OAuthLoginHandler):
    async def get(self):
        # load oidc configuration before handling login page
        if not self.authenticator.openid_configuration:
            await self.authenticator._load_openid_configuration()
        r = super().get()
        if inspect.isawaitable(r):
            await r


class OIDCOAuthenticator(OAuthenticator):
    """
    Subclass of OAuthenticator that loads configuration from OpenIDConnect

    Provider must provide OIDC Discovery 1.0.

    Typically only requires `OIDCOAuthenticator.openid_provider_url` to be set.

    ref: https://openid.net/specs/openid-connect-discovery-1_0.html

    - loads URLs from `${openid_provider_url}/.well-known/openid-configuration`
    - handles JWKs for token signing

    .. versionadded:: 17.5
    """

    login_handler = OIDCLoginHandler

    openid_provider_url = Unicode(
        config=True,
        help="""
        The base URL for the OpenID Connect (OIDC) provider.

        ${PROVIDER_URL}/.well-known/openid-configuration MUST exist.

        Examples:
        - `https://some-keycloak.domain/realms/realmname`
        - `https://accounts.google.com`
        - `https://samples.auth0.com`

        Required.
    """,
    )

    @default("openid_provider_url")
    def _openid_provider_url_default(self):
        return os.environ.get("OPENID_PROVIDER_URL", "")

    @default("username_claim")
    def _default_username_claim(self):
        # change default username claim to oidc-standard 'sub'
        return os.environ.get('OAUTH2_USERNAME_KEY', 'sub')

    # loaded from Discovery, not configurable
    openid_configuration = None
    _last_openid_configuration_fetch_time = None

    @default("scope")
    def _scope_default(self):
        return ["openid"]

    async def _load_openid_configuration(self):
        # for required/optional fields, see
        # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        if not self.openid_provider_url:
            raise ValueError(
                f"{self.__class__}.openid_provider_url unset. Please set it."
            )
        openid_configuration_url = (
            self.openid_provider_url.rstrip("/") + "/.well-known/openid-configuration"
        )
        self.log.info(f"Loading OIDC Configuration from {openid_configuration_url}")
        self.openid_configuration = cfg = await self.httpfetch(openid_configuration_url)
        self._last_openid_configuration_fetch_time = time.monotonic()
        # required fields
        self.jwt_issuer = cfg["issuer"]
        self.token_url = cfg["token_endpoint"]
        self.authorize_url = cfg["authorization_endpoint"]
        self.jwks_uri = cfg["jwks_uri"]

        # optional fields for OIDC, maybe optional for us
        if "userinfo_endpoint" in cfg:
            if not self.userdata_from_id_token:
                self.userdata_url = cfg["userinfo_endpoint"]
        elif not self.userdata_from_id_token:
            raise ValueError(
                f"userinfo_endpoint not found in {openid_configuration_url}, but userdata_from_id_token not set."
            )

        # optional fields
        if not self.logout_redirect_url:
            self.logout_redirect_url = cfg.get("end_session_endpoint", "")

    @wraps(OAuthenticator.authenticate)
    async def authenticate(self, *args, **kwargs):
        if not self.openid_configuration:
            await self._load_openid_configuration()
        return await super().authenticate(*args, **kwargs)

    def _token_to_auth_model(self, token_info):

        return super()._token_to_auth_model(token_info)


class LocalOIDCOAuthenticator(LocalAuthenticator, OIDCOAuthenticator):
    """A version that mixes in local system user creation"""
