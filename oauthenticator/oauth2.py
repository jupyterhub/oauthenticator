"""
Base classes for use by OAuth2 based JupyterHub authenticator classes.

Founded based on work by Kyle Kelley (@rgbkrk)
"""

import base64
import json
import os
import uuid
from urllib.parse import quote, urlencode, urlparse, urlunparse

import jwt
from jupyterhub.auth import Authenticator
from jupyterhub.crypto import EncryptionUnavailable, InvalidToken, decrypt
from jupyterhub.handlers import BaseHandler, LogoutHandler
from jupyterhub.utils import url_path_join
from tornado import web
from tornado.auth import OAuth2Mixin
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest
from tornado.httputil import url_concat
from tornado.log import app_log
from traitlets import Any, Bool, Callable, Dict, List, Unicode, Union, default, validate


def guess_callback_uri(protocol, host, hub_server_url):
    return f'{protocol}://{host}{url_path_join(hub_server_url, "oauth_callback")}'


STATE_COOKIE_NAME = "oauthenticator-state"


def _serialize_state(state):
    """Serialize OAuth state to a base64 string after passing through JSON"""
    json_state = json.dumps(state)
    return base64.urlsafe_b64encode(json_state.encode("utf8")).decode("ascii")


def _deserialize_state(b64_state):
    """Deserialize OAuth state as serialized in _serialize_state"""
    if isinstance(b64_state, str):
        b64_state = b64_state.encode("ascii")
    try:
        json_state = base64.urlsafe_b64decode(b64_state).decode("utf8")
    except ValueError:
        app_log.error(f"Failed to b64-decode state: {b64_state}")
        return {}
    try:
        return json.loads(json_state)
    except ValueError:
        app_log.error(f"Failed to json-decode state: {json_state}")
        return {}


class OAuthLoginHandler(OAuth2Mixin, BaseHandler):
    """Base class for OAuth login handler

    Typically subclasses will need
    """

    # these URLs are part of the OAuth2Mixin API
    # get them from the Authenticator object
    @property
    def _OAUTH_AUTHORIZE_URL(self):
        return self.authenticator.authorize_url

    @property
    def _OAUTH_ACCESS_TOKEN_URL(self):
        return self.authenticator.token_url

    @property
    def _OAUTH_USERINFO_URL(self):
        return self.authenticator.userdata_url

    def set_state_cookie(self, state_cookie_value):
        self._set_cookie(
            STATE_COOKIE_NAME, state_cookie_value, expires_days=1, httponly=True
        )

    def _generate_state_id(self):
        return uuid.uuid4().hex

    def _get_next_url(self):
        next_url = self.get_argument("next", None)
        if next_url:
            # avoid browsers treating \ as /
            next_url = next_url.replace("\\", quote("\\"))
            # disallow hostname-having urls,
            # force absolute path redirect
            urlinfo = urlparse(next_url)
            next_url = urlinfo._replace(
                scheme="", netloc="", path="/" + urlinfo.path.lstrip("/")
            ).geturl()
            return next_url

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        token_params = self.authenticator.extra_authorize_params.copy()
        self.log.info(f"OAuth redirect: {redirect_uri}")

        state_id = self._generate_state_id()
        next_url = self._get_next_url()

        cookie_state = _serialize_state({"state_id": state_id, "next_url": next_url})
        self.set_state_cookie(cookie_state)

        authorize_state = _serialize_state({"state_id": state_id})
        token_params["state"] = authorize_state

        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=self.authenticator.scope,
            extra_params=token_params,
            response_type="code",
        )


class OAuthCallbackHandler(BaseHandler):
    """Basic handler for OAuth callback. Calls authenticator to verify username."""

    _state_cookie = None

    def get_state_cookie(self):
        """Get OAuth state from cookies

        To be compared with the value in redirect URL
        """
        if self._state_cookie is None:
            self._state_cookie = (
                self.get_secure_cookie(STATE_COOKIE_NAME) or b""
            ).decode("utf8", "replace")
            self.clear_cookie(STATE_COOKIE_NAME)
        return self._state_cookie

    def get_state_url(self):
        """Get OAuth state from URL parameters

        to be compared with the value in cookies
        """
        return self.get_argument("state")

    def check_state(self):
        """Verify OAuth state

        compare value in cookie with redirect url param
        """
        cookie_state = self.get_state_cookie()
        url_state = self.get_state_url()
        if not cookie_state:
            raise web.HTTPError(400, "OAuth state missing from cookies")
        if not url_state:
            raise web.HTTPError(400, "OAuth state missing from URL")
        cookie_state_id = _deserialize_state(cookie_state).get('state_id')
        url_state_id = _deserialize_state(url_state).get('state_id')
        if cookie_state_id != url_state_id:
            self.log.warning(
                f"OAuth state mismatch: {cookie_state_id} != {url_state_id}"
            )
            raise web.HTTPError(400, "OAuth state mismatch")

    def check_error(self):
        """Check the OAuth code"""
        error = self.get_argument("error", False)
        if error:
            message = self.get_argument("error_description", error)
            raise web.HTTPError(400, f"OAuth error: {message}")

    def check_code(self):
        """Check the OAuth code"""
        if not self.get_argument("code", False):
            raise web.HTTPError(400, "OAuth callback made without a code")

    def check_arguments(self):
        """Validate the arguments of the redirect

        Default:

        - check for oauth-standard error, error_description arguments
        - check that there's a code
        - check that state matches
        """
        self.check_error()
        self.check_code()
        self.check_state()

    def append_query_parameters(self, url, exclude=None):
        """JupyterHub 1.2 appends query parameters by default in get_next_url

        This is not appropriate for oauth callback handlers, where params are oauth state, code, etc.

        Override the method used to append parameters to next_url to not preserve any parameters
        """
        return url

    def get_next_url(self, user=None):
        """Get the redirect target from the state field"""
        state = self.get_state_cookie()
        if state:
            next_url = _deserialize_state(state).get("next_url")
            if next_url:
                return next_url
        # JupyterHub 0.8 adds default .get_next_url for a fallback
        if hasattr(BaseHandler, "get_next_url"):
            return super().get_next_url(user)
        return url_path_join(self.hub.server.base_url, "home")

    async def get(self):
        self.check_arguments()
        user = await self.login_user()
        if user is None:
            raise web.HTTPError(403, self.authenticator.custom_403_message)

        self.redirect(self.get_next_url(user))


class OAuthLogoutHandler(LogoutHandler):
    async def handle_logout(self):
        self.clear_cookie(STATE_COOKIE_NAME)

    async def render_logout_page(self):
        if self.authenticator.logout_redirect_url:
            self.redirect(self.authenticator.logout_redirect_url)
            return

        return await super().render_logout_page()


class OAuthenticator(Authenticator):
    """
    Base class for OAuthenticators.

    Subclasses should, in an increasing level of customization:

    - Override the constant `user_auth_state_key`
    - Override various config's default values, such as
      `authorize_url`, `token_url`, `userdata_url`, and `login_service`.
    - Override various methods called by the `authenticate` method, which
      subclasses should not override.
    - Override handler classes such as `login_handler`, `callback_handler`, and
      `logout_handler`.
    """

    login_handler = OAuthLoginHandler
    callback_handler = OAuthCallbackHandler
    logout_handler = OAuthLogoutHandler

    # user_auth_state_key represents the name of the key in the `auth_state`
    # dictionary that user info will be saved
    user_auth_state_key = "oauth_user"

    login_service = Unicode(
        "OAuth 2.0",
        config=True,
        help="""
        Name of the login service or identity provider that this authenticator
        is using to authenticate users.

        This config influences the text on a button shown to unauthenticated
        users before they click it to login, assuming :attr:`auto_login` isn't
        configured True.

        The login button's text will be "Login with <login_service>".
        """,
    )

    allow_all = Bool(
        False,
        config=True,
        help="""
        Allow all authenticated users to login.

        Overrides all other `allow` configuration.

        .. versionadded:: 16.0
        """,
    )

    allow_existing_users = Bool(
        False,
        config=True,
        help="""
        Allow existing users to login.

        Enable this if you want to manage user access via the JupyterHub admin page (/hub/admin).

        With this enabled, all users present in the JupyterHub database are allowed to login.
        This has the effect of any user who has _previously_ been allowed to login
        via any means will continue to be allowed until the user is deleted via the /hub/admin page
        or REST API.

        .. warning::

           Before enabling this you should review the existing users in the
           JupyterHub admin panel at `/hub/admin`. You may find users existing
           there because they have previously been declared in config such as
           `allowed_users` or allowed to sign in.

        .. warning::

           When this is enabled and you wish to remove access for one or more
           users previously allowed, you must make sure that they
           are removed from the jupyterhub database. This can be tricky to do
           if you stop allowing a group of externally managed users for example.

        With this enabled, JupyterHub admin users can visit `/hub/admin` or use
        JupyterHub's REST API to add and remove users to manage who can login.

        .. versionadded:: 16.0

        .. versionchanged:: 16.0

           Before this config was available, the default behavior was to allow
           existing users if `allowed_users` was configured with one or more
           user.
        """,
    )

    authorize_url = Unicode(
        config=True,
        help="""
        The URL to where the user is to be redirected initially based on the
        OAuth2 protocol. The user will be redirected back with an
        `authorization grant code`_ after authenticating successfully with the
        identity provider.

        .. _authorization grant code: https://www.rfc-editor.org/rfc/rfc6749#section-1.3.1

        For more context, see the `Protocol Flow section
        <https://www.rfc-editor.org/rfc/rfc6749#section-1.2>`_ in the OAuth2
        standard document, specifically steps A-B.
        """,
    )

    @default("authorize_url")
    def _authorize_url_default(self):
        return os.environ.get("OAUTH2_AUTHORIZE_URL", "")

    token_url = Unicode(
        config=True,
        help="""
        The URL to where this authenticator makes a request to acquire an
        `access token`_ based on the authorization code received by the user
        returning from the :attr:`authorize_url`.

        .. _access token: https://www.rfc-editor.org/rfc/rfc6749#section-1.4

        For more context, see the `Protocol Flow section
        <https://www.rfc-editor.org/rfc/rfc6749#section-1.2>`_ in the OAuth2
        standard document, specifically steps C-D.
        """,
    )

    @default("token_url")
    def _token_url_default(self):
        return os.environ.get("OAUTH2_TOKEN_URL", "")

    userdata_from_id_token = Bool(
        False,
        config=True,
        help="""
        Extract user details from an id token received via a request to
        :attr:`token_url`, rather than making a follow-up request to the
        userinfo endpoint :attr:`userdata_url`.

        Should only be used if :attr:`token_url` uses HTTPS, to ensure
        token authenticity.

        For more context, see `Authentication using the Authorization
        Code Flow
        <https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth>`_
        in the OIDC Core standard document.
        """,
    )

    userdata_url = Unicode(
        config=True,
        help="""
        The URL to where this authenticator makes a request to acquire user
        details with an access token received via a request to the
        :attr:`token_url`.

        For more context, see the `Protocol Flow section
        <https://www.rfc-editor.org/rfc/rfc6749#section-1.2>`_ in the OAuth2
        standard document, specifically steps E-F.

        Incompatible with :attr:`userdata_from_id_token`.
        """,
    )

    @default("userdata_url")
    def _userdata_url_default(self):
        return os.environ.get("OAUTH2_USERDATA_URL", "")

    @validate("userdata_url")
    def _validate_userdata_url(self, proposal):
        if proposal.value and self.userdata_from_id_token:
            raise ValueError(
                "Cannot specify both authenticator.userdata_url and authenticator.userdata_from_id_token."
            )
        return proposal.value

    username_claim = Union(
        [Unicode(os.environ.get('OAUTH2_USERNAME_KEY', 'username')), Callable()],
        config=True,
        help="""
        When `userdata_url` returns a json response, the username will be taken
        from this key.

        Can be a string key name or a callable that accepts the returned
        userdata json (as a dict) and returns the username.  The callable is
        useful e.g. for extracting the username from a nested object in the
        response or doing other post processing.

        What keys are available will depend on the scopes requested and the
        authenticator used.
        """,
    )

    # Enable refresh_pre_spawn by default if self.enable_auth_state
    @default("refresh_pre_spawn")
    def _refresh_pre_spawn_default(self):
        if self.enable_auth_state:
            return True

        return False

    logout_redirect_url = Unicode(
        config=True,
        help="""
        When configured, users are not presented with the JupyterHub logout
        page, but instead redirected to this destination.
        """,
    )

    @default("logout_redirect_url")
    def _logout_redirect_url_default(self):
        return os.getenv("OAUTH_LOGOUT_REDIRECT_URL", "")

    # Originally a GenericOAuthenticator only trait
    userdata_params = Dict(
        config=True,
        help="""
        Userdata params to get user data login information.
        """,
    )

    # Originally a GenericOAuthenticator only trait
    userdata_token_method = Unicode(
        os.environ.get("OAUTH2_USERDATA_REQUEST_TYPE", "header"),
        config=True,
        help="""
        Method for sending access token in userdata request.

        Supported methods: header, url.
        """,
    )

    # Originally a GenericOAuthenticator only trait
    token_params = Dict(
        config=True,
        help="""
        Extra parameters for first POST request exchanging the OAuth code for an
        Access Token
        """,
    )

    custom_403_message = Unicode(
        "Sorry, you are not currently authorized to use this hub. Please contact the hub administrator.",
        config=True,
        help="""
        The message to be shown when user was not allowed
        """,
    )

    scope = List(
        Unicode(),
        config=True,
        help="""
        The OAuth scopes to request.

        See the OAuth documentation of your OAuth provider for options.
        """,
    )

    extra_authorize_params = Dict(
        config=True,
        help="""
        Extra GET params to send along with the initial OAuth request to the
        OAuth provider.
        """,
    )

    oauth_callback_url = Unicode(
        os.getenv("OAUTH_CALLBACK_URL", ""),
        config=True,
        help="""
        Callback URL to use.

        When registering an OAuth2 application with an identity provider, this
        is typically called the redirect url.

        Should very likely be set to `https://[your-domain]/hub/oauth_callback`.
        """,
    )

    # Originally a GenericOAuthenticator only trait
    basic_auth = Bool(
        os.environ.get("OAUTH2_BASIC_AUTH", "False").lower() in {"true", "1"},
        config=True,
        help="""
        Whether or to use HTTP Basic authentication instead of form based
        authentication in requests to :attr:`token_url`.

        When using HTTP Basic authentication, a HTTP header is set with the
        :attr:`client_id` and :attr:`client_secret` encoded in it.

        When using form based authentication, the `client_id` and
        `client_secret` is put in the HTTP POST request's body.

        .. versionchanged:: 16.0.0

           This configuration now toggles between HTTP Basic authentication and
           form based authentication when working against the `token_url`.

           Previously when this was configured True, both would be used contrary
           to a recommendation in `OAuth 2.0 documentation
           <https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1>`_.

        .. versionchanged:: 16.0.2

           The default value for this configuration for GenericOAuthenticator
           changed from True to False.
        """,
    )

    client_id_env = ""
    client_id = Unicode(
        config=True,
        help="""
        The client id of the OAuth2 application registered with the identity
        provider.
        """,
    )

    def _client_id_default(self):
        if self.client_id_env:
            client_id = os.getenv(self.client_id_env, "")
            if client_id:
                return client_id
        return os.getenv("OAUTH_CLIENT_ID", "")

    client_secret_env = ""
    client_secret = Unicode(
        config=True,
        help="""
        The client secret of the OAuth2 application registered with the identity
        provider.
        """,
    )

    def _client_secret_default(self):
        if self.client_secret_env:
            client_secret = os.getenv(self.client_secret_env, "")
            if client_secret:
                return client_secret
        return os.getenv("OAUTH_CLIENT_SECRET", "")

    validate_server_cert_env = "OAUTH_TLS_VERIFY"
    validate_server_cert = Bool(
        config=True,
        help="""
        Determines if certificates are validated.

        Only set this to False if you feel confident it will not be a security
        concern.
        """,
    )

    def _validate_server_cert_default(self):
        env_value = os.getenv(self.validate_server_cert_env, "")
        if env_value == "0":
            return False
        else:
            return True

    http_request_kwargs = Dict(
        config=True,
        help="""
        Extra default kwargs passed to all HTTPRequests.

        .. code-block:: python

            # Example: send requests through a proxy
            c.OAuthenticator.http_request_kwargs = {
                "proxy_host": "proxy.example.com",
                "proxy_port": 8080,
            }

            # Example: validate against certain root certificates
            c.OAuthenticator.http_request_kwargs = {
                "ca_certs": "/path/to/a.crt",
            }

        See :external:py:class:`tornado.httpclient.HTTPRequest` for all kwargs
        options you can pass. Note that the HTTP client making these requests is
        :external:py:class:`tornado.httpclient.AsyncHTTPClient`.
        """,
    )

    http_client = Any()

    @default("http_client")
    def _default_http_client(self):
        return AsyncHTTPClient()

    async def fetch(self, req, label="fetching", parse_json=True, **kwargs):
        """Wrapper for http requests

        logs error responses, parses successful JSON responses

        Args:
            req: tornado HTTPRequest
            label (str): label describing what is happening,
                used in log message when the request fails.
            parse_json (bool): whether to parse the response as JSON
            **kwargs: remaining keyword args
                passed to underlying `client.fetch(req, **kwargs)`
        Returns:
            parsed JSON response if `parse_json=True`, else `tornado.HTTPResponse`
        """
        try:
            resp = await self.http_client.fetch(req, **kwargs)
        except HTTPClientError as e:
            if e.response:
                # Log failed response message for debugging purposes
                message = e.response.body.decode("utf8", "replace")
                try:
                    # guess json, reformat for readability
                    json_message = json.loads(message)
                except ValueError:
                    # not json
                    pass
                else:
                    # reformat json log message for readability
                    message = json.dumps(json_message, sort_keys=True, indent=1)
            else:
                # didn't get a response, e.g. connection error
                message = str(e)

            # log url without query params
            url = urlunparse(urlparse(req.url)._replace(query=""))
            app_log.error(f"Error {label} {e.code} {req.method} {url}: {message}")
            raise e
        else:
            if parse_json:
                if resp.body:
                    return json.loads(resp.body.decode("utf8", "replace"))
                else:
                    # empty body is None
                    return None
            else:
                return resp

    async def httpfetch(
        self, url, label="fetching", parse_json=True, raise_error=True, **kwargs
    ):
        """Wrapper for creating and fetching http requests

        Includes http_request_kwargs in request kwargs
        logs error responses, parses successful JSON responses

        Args:
            url (str): url to fetch
            label (str): label describing what is happening,
                used in log message when the request fails.
            parse_json (bool): whether to parse the response as JSON
            raise_error (bool): whether to raise an exception on HTTP errors
            **kwargs: remaining keyword args
                passed to underlying `tornado.HTTPRequest`, overrides
                `http_request_kwargs`
        Returns:
            parsed JSON response if `parse_json=True`, else `tornado.HTTPResponse`
        """
        request_kwargs = self.http_request_kwargs.copy()
        request_kwargs.update(kwargs)
        req = HTTPRequest(url, **request_kwargs)
        return await self.fetch(
            req, label=label, parse_json=parse_json, raise_error=raise_error
        )

    def add_user(self, user):
        """
        Overrides `Authenticator.add_user`, a hook called for all users in the
        database on startup and for each user being created.

        The purpose of the override is to implement the `allow_existing_users`
        config by adding users to the `allowed_users` set only if
        `allow_existing_users` is truthy. The overridden behavior is to do it if
        `allowed_users` is truthy.

        The implementation is adjusted from JupyterHub 4.0.1:
        https://github.com/jupyterhub/jupyterhub/blob/4.0.1/jupyterhub/auth.py#L625-L648
        """
        if not self.validate_username(user.name):
            raise ValueError("Invalid username: %s" % user.name)
        if not self.allow_all and self.allow_existing_users:
            self.allowed_users.add(user.name)

    def login_url(self, base_url):
        return url_path_join(base_url, "oauth_login")

    def logout_url(self, base_url):
        return url_path_join(base_url, "logout")

    def get_callback_url(self, handler=None):
        """Get my OAuth redirect URL

        Either from config or guess based on the current request.
        """
        if self.oauth_callback_url:
            return self.oauth_callback_url
        elif handler:
            return guess_callback_uri(
                handler.request.protocol,
                handler.request.host,
                handler.hub.server.base_url,
            )
        else:
            raise ValueError(
                "Specify callback oauth_callback_url or give me a handler to guess with"
            )

    def get_handlers(self, app):
        return [
            (r"/oauth_login", self.login_handler),
            (r"/oauth_callback", self.callback_handler),
            (r"/logout", self.logout_handler),
        ]

    def build_userdata_request_headers(self, access_token, token_type):
        """
        Builds and returns the headers to be used in the userdata request.
        Called by the :meth:`oauthenticator.OAuthenticator.token_to_user`
        """

        # token_type is case-insensitive, but the headers are case-sensitive
        if token_type.lower() == "bearer":
            auth_token_type = "Bearer"
        else:
            auth_token_type = token_type

        return {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": f"{auth_token_type} {access_token}",
        }

    def build_token_info_request_headers(self):
        """
        Builds and returns the headers to be used in the access token request.
        Called by the :meth:`oauthenticator.OAuthenticator.get_token_info`.

        The Content-Type header is specified by the OAuth 2.0 RFC in
        https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3. utf-8 is also
        required according to https://www.rfc-editor.org/rfc/rfc6749#appendix-B,
        and that can be specified with a Content-Type directive according to
        https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type#directives.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "User-Agent": "JupyterHub",
        }

        if self.basic_auth:
            b64key = base64.b64encode(
                bytes(f"{self.client_id}:{self.client_secret}", "utf8")
            )
            headers.update({"Authorization": f'Basic {b64key.decode("utf8")}'})
        return headers

    def user_info_to_username(self, user_info):
        """
        Gets the self.username_claim key's value from the user_info dictionary.

        Should be overridden by the authenticators for which the hub username cannot
        be extracted this way and needs extra processing.

        Args:
            user_info: the dictionary returned by the userdata request

        Returns:
            user_info["self.username_claim"] or raises an error if such value isn't found.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """

        if callable(self.username_claim):
            username = self.username_claim(user_info)
        else:
            username = user_info.get(self.username_claim, None)
        if not username:
            message = (f"No {self.username_claim} found in {user_info}",)
            self.log.error(message)
            raise ValueError(message)

        return username

    # Originally a GoogleOAuthenticator only feature
    async def get_prev_refresh_token(self, handler, username):
        """
        Retrieves the `refresh_token` from previous encrypted auth state.
        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        user = handler.find_user(username)
        if not user or not user.encrypted_auth_state:
            return

        self.log.debug(
            "Encrypted_auth_state was found, will try to decrypt and pull refresh_token from it..."
        )

        try:
            encrypted = user.encrypted_auth_state
            auth_state = await decrypt(encrypted)

            return auth_state.get("refresh_token")
        except (ValueError, InvalidToken, EncryptionUnavailable) as e:
            self.log.warning(
                f"Failed to retrieve encrypted auth_state for {username}. Error was {e}.",
            )
            return

    def build_access_tokens_request_params(self, handler, data=None):
        """
        Builds the parameters that should be passed to the URL request
        that exchanges the OAuth code for the Access Token.
        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`.
        """
        code = handler.get_argument("code")
        if not code:
            raise web.HTTPError(400, "Authentication Cancelled.")

        params = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.get_callback_url(handler),
            "data": data,
        }

        # the client_id and client_secret should not be included in the access token request params
        # when basic authentication is used
        # ref: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
        if not self.basic_auth:
            params.update(
                [("client_id", self.client_id), ("client_secret", self.client_secret)]
            )

        params.update(self.token_params)

        return params

    async def get_token_info(self, handler, params):
        """
        Makes a "POST" request to `self.token_url`, with the parameters received as argument.

        Returns:
            the JSON response to the `token_url` the request.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """

        token_info = await self.httpfetch(
            self.token_url,
            method="POST",
            headers=self.build_token_info_request_headers(),
            body=urlencode(params).encode("utf-8"),
            validate_cert=self.validate_server_cert,
        )

        if "error_description" in token_info:
            raise web.HTTPError(
                403,
                f'An access token was not returned: {token_info["error_description"]}',
            )
        elif "access_token" not in token_info:
            raise web.HTTPError(500, f"Bad response: {token_info}")

        return token_info

    async def token_to_user(self, token_info):
        """
        Determines who the logged-in user by sending a "GET" request to
        :data:`oauthenticator.OAuthenticator.userdata_url` using the `access_token`.

        If :data:`oauthenticator.OAuthenticator.userdata_from_id_token` is set then
        extracts the corresponding info from an `id_token` instead.

        Args:
            token_info: the dictionary returned by the token request (exchanging the OAuth code for an Access Token)

        Returns:
            the JSON response to the `userdata_url` request.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        if self.userdata_from_id_token:
            # Use id token instead of exchanging access token with userinfo endpoint.
            id_token = token_info.get("id_token", None)
            if not id_token:
                raise web.HTTPError(
                    500,
                    f"An id token was not returned: {token_info}\nPlease configure authenticator.userdata_url",
                )
            try:
                # Here we parse the id token. Note that per OIDC spec (core v1.0 sect. 3.1.3.7.6) we can skip
                # signature validation as the hub has obtained the tokens from the id provider directly (using
                # https). Google suggests all token validation may be skipped assuming the provider is trusted.
                # https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                # https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
                return jwt.decode(
                    id_token,
                    audience=self.client_id,
                    options=dict(
                        verify_signature=False, verify_aud=True, verify_exp=True
                    ),
                )
            except Exception as err:
                raise web.HTTPError(
                    500, f"Unable to decode id token: {id_token}\n{err}"
                )

        access_token = token_info["access_token"]
        token_type = token_info["token_type"]

        if not self.userdata_url:
            raise ValueError(
                "authenticator.userdata_url is missing. Please configure it."
            )

        url = url_concat(self.userdata_url, self.userdata_params)
        if self.userdata_token_method == "url":
            url = url_concat(url, dict(access_token=access_token))

        return await self.httpfetch(
            url,
            "Fetching user info...",
            method="GET",
            headers=self.build_userdata_request_headers(access_token, token_type),
            validate_cert=self.validate_server_cert,
        )

    def build_auth_state_dict(self, token_info, user_info):
        """
        Builds the `auth_state` dict that will be returned by a succesfull `authenticate` method call.

        Args:
            token_info: the dictionary returned by the token request (exchanging the OAuth code for an Access Token)
            user_info: the dictionary returned by the userdata request

        Returns:
            auth_state: a dictionary of auth state that should be persisted with the following keys:
                - "access_token": the access_token
                - "refresh_token": the refresh_token, if available
                - "id_token": the id_token, if available
                - "scope": the scopes, if available
                - "token_response": the full token_info response
                - self.user_auth_state_key: the full user_info response

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """

        # We know for sure the `access_token` key exists, oterwise we would have errored out already
        access_token = token_info["access_token"]

        refresh_token = token_info.get("refresh_token", None)
        id_token = token_info.get("id_token", None)
        scope = token_info.get("scope", "")

        if isinstance(scope, str):
            scope = scope.split(" ")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "scope": scope,
            # Save the full token response
            # These can be used for user provisioning in the Lab/Notebook environment.
            "token_response": token_info,
            # store the whole user model in auth_state too
            self.user_auth_state_key: user_info,
        }

    async def update_auth_model(self, auth_model):
        """
        Updates and returns the `auth_model` dict.

        Should be overridden to collect information required for check_allowed.

        Args: auth_model - the auth model dictionary, containing:
            - `name`: the normalized username
            - `admin`: the admin status (True/False/None), where None means it
                should be unchanged.
            - `auth_state`: the dictionary of of auth state
                returned by :meth:`oauthenticator.OAuthenticator.build_auth_state_dict`

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        return auth_model

    async def authenticate(self, handler, data=None, **kwargs):
        """
        A JupyterHub Authenticator's authenticate method's job is:

        - return None if the user isn't successfully authenticated
        - return a dictionary if authentication is successful with name, admin
          (optional), and auth_state (optional)

        Subclasses should not override this method.

        ref: https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#authenticator-authenticate-method
        ref: https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/auth.py#L581-L611
        """
        # build the parameters to be used in the request exchanging the oauth code for the access token
        access_token_params = self.build_access_tokens_request_params(handler, data)
        # exchange the oauth code for an access token and get the JSON with info about it
        token_info = await self.get_token_info(handler, access_token_params)
        # use the access_token to get userdata info
        user_info = await self.token_to_user(token_info)
        # extract the username out of the user_info dict and normalize it
        username = self.user_info_to_username(user_info)
        username = self.normalize_username(username)

        # check if there any refresh_token in the token_info dict
        refresh_token = token_info.get("refresh_token", None)
        if self.enable_auth_state and not refresh_token:
            self.log.debug(
                "Refresh token was empty, will try to pull refresh_token from previous auth_state"
            )
            refresh_token = await self.get_prev_refresh_token(handler, username)
            if refresh_token:
                token_info["refresh_token"] = refresh_token

        # build the auth model to be read if authentication goes right
        auth_model = {
            "name": username,
            "admin": True if username in self.admin_users else None,
            "auth_state": self.build_auth_state_dict(token_info, user_info),
        }

        # update the auth_model with info to later authorize the user in
        # check_allowed, such as admin status and group memberships
        return await self.update_auth_model(auth_model)

    async def check_allowed(self, username, auth_model):
        """
        Returns True for users allowed to be authorized

        Overrides Authenticator.check_allowed that is called from
        `Authenticator.get_authenticated_user` after
        `OAuthenticator.authenticate` has been called, and therefore also after
        `update_auth_model` has been called.

        Subclasses with additional config to allow a user should override this
        method and return True when this method returns True or if a user is
        allowed via the additional config.
        """
        # A workaround for JupyterHub < 5.0 described in
        # https://github.com/jupyterhub/oauthenticator/issues/621
        if auth_model is None:
            return True

        if self.allow_all:
            return True

        # allow users with admin status set to True via admin_users config or
        # update_auth_model override
        if auth_model["admin"]:
            return True

        # allow users in allowed_users, note that allowed_users is appended
        # automatically with existing users if it was configured truthy
        if username in self.allowed_users:
            return True

        # users should be explicitly allowed via config, otherwise they aren't
        return False

    # _deprecated_oauth_aliases should be a dictionary with a format as:
    #
    # {
    #     "old_config": (
    #         "new_config",
    #         "16.0.0",      # version when it became deprecated
    #         False,         # if new config can be updated with a warning
    #     ),
    # }
    #
    _deprecated_oauth_aliases = {}

    def _deprecated_oauth_trait(self, change):
        """observer for deprecated traits"""
        old_attr = change.name
        try:
            new_attr, version, same = self._deprecated_oauth_aliases.get(old_attr)
        except ValueError:
            # if `same` flag wasn't passed, we assume the new and old trait have the same type
            new_attr, version = self._deprecated_oauth_aliases.get(old_attr)
            same = True

        new_value = getattr(self, new_attr)
        if new_value != change.new:
            # only warn if different
            # protects backward-compatible config from warnings
            # if they set the same value under both names
            message = "{cls}.{old} is deprecated in {cls} {version}, use {cls}.{new} instead".format(
                cls=self.__class__.__name__,
                old=old_attr,
                new=new_attr,
                version=version,
            )

            # set the value for the new attr only if they are the same type
            # otherwise raise an error because unexpected things can happen
            if same:
                self.log.warning(message)
                setattr(self, new_attr, change.new)
            else:
                self.log.error(message)
                raise ValueError(message)

    def __init__(self, **kwargs):
        # observe deprecated config names in oauthenticator
        if self._deprecated_oauth_aliases:
            self.observe(
                self._deprecated_oauth_trait, names=list(self._deprecated_oauth_aliases)
            )
        super().__init__(**kwargs)


# patch allowed_users help string to match our definition
# base Authenticator class help string gives the wrong impression
# when combined with other allow options
OAuthenticator.class_traits()[
    "allowed_users"
].help = """
Set of usernames that should be allowed to login.

If unspecified, grants no access. You must set at least one other `allow` configuration
if any users are to have permission to access the Hub.

Any usernames in `admin_users` will also be allowed to login.
"""
