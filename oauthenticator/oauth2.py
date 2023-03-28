"""
Base classes for Custom Authenticator to use OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""
import base64
import json
import os
import time
import uuid
from urllib.parse import quote, urlparse, urlunparse

from jupyterhub.auth import Authenticator
from jupyterhub.crypto import EncryptionUnavailable, InvalidToken, decrypt
from jupyterhub.handlers import BaseHandler, LogoutHandler
from jupyterhub.utils import url_path_join
from tornado import web
from tornado.auth import OAuth2Mixin
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest
from tornado.httputil import url_concat
from tornado.log import app_log
from traitlets import Any, Bool, Dict, List, Unicode, default


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

    def set_state_cookie(self, state):
        self._set_cookie(STATE_COOKIE_NAME, state, expires_days=1, httponly=True)

    _state = None

    def get_state(self):
        next_url = original_next_url = self.get_argument("next", None)
        if next_url:
            # avoid browsers treating \ as /
            next_url = next_url.replace("\\", quote("\\"))
            # disallow hostname-having urls,
            # force absolute path redirect
            urlinfo = urlparse(next_url)
            next_url = urlinfo._replace(
                scheme="", netloc="", path="/" + urlinfo.path.lstrip("/")
            ).geturl()
            if next_url != original_next_url:
                self.log.warning(
                    f"Ignoring next_url {original_next_url}, using {next_url}"
                )
        if self._state is None:
            self._state = _serialize_state(
                {"state_id": uuid.uuid4().hex, "next_url": next_url}
            )
        return self._state

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        token_params = self.authenticator.extra_authorize_params.copy()
        self.log.info(f"OAuth redirect: {redirect_uri}")
        state = self.get_state()
        self.set_state_cookie(state)
        token_params["state"] = state
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
        if cookie_state != url_state:
            self.log.warning(f"OAuth state mismatch: {cookie_state} != {url_state}")
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
        state = self.get_state_url()
        if state:
            next_url = _deserialize_state(state).get("next_url")
            if next_url:
                return next_url
        # JupyterHub 0.8 adds default .get_next_url for a fallback
        if hasattr(BaseHandler, "get_next_url"):
            return super().get_next_url(user)
        return url_path_join(self.hub.server.base_url, "home")

    async def _login_user_pre_08(self):
        """login_user simplifies the login+cookie+auth_state process in JupyterHub 0.8

        _login_user_07 is for backward-compatibility with JupyterHub 0.7
        """
        user_info = await self.authenticator.get_authenticated_user(self, None)
        if user_info is None:
            return
        if isinstance(user_info, dict):
            username = user_info["name"]
        else:
            username = user_info
        user = self.user_from_username(username)
        self.set_login_cookie(user)
        return user

    if not hasattr(BaseHandler, "login_user"):
        # JupyterHub 0.7 doesn't have .login_user
        login_user = _login_user_pre_08

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
    """Base class for OAuthenticators

    Subclasses must override:

    login_service (string identifying the service provider)
    authenticate (method takes one arg - the request handler handling the oauth callback)
    """

    login_handler = OAuthLoginHandler
    callback_handler = OAuthCallbackHandler
    logout_handler = OAuthLogoutHandler

    user_auth_state_key = Unicode(
        "oauth_user",
        config=True,
        help="""The name of the user key expected to be present in `auth_state`.""",
    )

    authorize_url = Unicode(
        config=True, help="""The authenticate url for initiating oauth"""
    )

    @default("authorize_url")
    def _authorize_url_default(self):
        return os.environ.get("OAUTH2_AUTHORIZE_URL", "")

    token_url = Unicode(
        config=True,
        help="""The url retrieving an access token at the completion of oauth""",
    )

    @default("token_url")
    def _token_url_default(self):
        return os.environ.get("OAUTH2_TOKEN_URL", "")

    userdata_url = Unicode(
        config=True,
        help="""The url for retrieving user data with a completed access token""",
    )

    @default("userdata_url")
    def _userdata_url_default(self):
        return os.environ.get("OAUTH2_USERDATA_URL", "")

    username_claim = Unicode(
        "username",
        config=True,
        help="""Field in userdata reply to use for username
        The field in the userdata response from which to get the JupyterHub username.
        Examples include: email, username, nickname

        What keys are available will depend on the scopes requested and the authenticator used.
        """,
    )

    # Enable refresh_pre_spawn by default if self.enable_auth_state
    @default("refresh_pre_spawn")
    def _refresh_pre_spawn(self):
        if self.enable_auth_state:
            return True

        return False

    logout_redirect_url = Unicode(config=True, help="""URL for logging out of Auth0""")

    # Originally a GenericOAuthenticator only trait
    userdata_params = Dict(
        help="Userdata params to get user data login information"
    ).tag(config=True)

    # Originally a GenericOAuthenticator only trait
    userdata_token_method = Unicode(
        os.environ.get("OAUTH2_USERDATA_REQUEST_TYPE", "header"),
        config=True,
        help="Method for sending access token in userdata request. Supported methods: header, url. Default: header",
    )

    # Originally a GenericOAuthenticator only trait
    token_params = Dict(
        help="Extra parameters for first POST request exchanging the OAuth code for an Access Token"
    ).tag(config=True)

    @default("logout_redirect_url")
    def _logout_redirect_url_default(self):
        return os.getenv("OAUTH_LOGOUT_REDIRECT_URL", "")

    custom_403_message = Unicode(
        "Sorry, you are not currently authorized to use this hub. Please contact the hub administrator.",
        config=True,
        help="""The message to be shown when user was not allowed""",
    )

    scope = List(
        Unicode(),
        config=True,
        help="""The OAuth scopes to request.
        See the OAuth documentation of your OAuth provider for options.
        For GitHub in particular, you can see github_scopes.md in this repo.
        """,
    )

    extra_authorize_params = Dict(
        config=True,
        help="""Extra GET params to send along with the initial OAuth request
        to the OAuth provider.""",
    )

    login_service = "override in subclass"
    oauth_callback_url = Unicode(
        os.getenv("OAUTH_CALLBACK_URL", ""),
        config=True,
        help="""Callback URL to use.
        Typically `https://{host}/hub/oauth_callback`""",
    )

    # Originally a GenericOAuthenticator only trait
    basic_auth = Bool(
        os.environ.get("OAUTH2_BASIC_AUTH", "False").lower() in {"false", "0"},
        config=True,
        help="Whether or not to use basic authentication for access token request",
    )

    client_id_env = ""
    client_id = Unicode(config=True)

    def _client_id_default(self):
        if self.client_id_env:
            client_id = os.getenv(self.client_id_env, "")
            if client_id:
                return client_id
        return os.getenv("OAUTH_CLIENT_ID", "")

    client_secret_env = ""
    client_secret = Unicode(config=True)

    def _client_secret_default(self):
        if self.client_secret_env:
            client_secret = os.getenv(self.client_secret_env, "")
            if client_secret:
                return client_secret
        return os.getenv("OAUTH_CLIENT_SECRET", "")

    access_token_expiration_env = "OAUTH_ACCESS_TOKEN_EXPIRATION"
    access_token_expiration = Unicode(
        config=True, help="""Default expiration, in seconds, of the access token."""
    )

    def _access_token_expiration_default(self):
        return os.getenv(self.access_token_expiration_env, "3600")

    validate_server_cert_env = "OAUTH_TLS_VERIFY"
    validate_server_cert = Bool(config=True)

    def _validate_server_cert_default(self):
        env_value = os.getenv(self.validate_server_cert_env, "")
        if env_value == "0":
            return False
        else:
            return True

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
            **kwargs: remaining keyword args
                passed to underlying `client.fetch(req, **kwargs)`
        Returns:
            r: parsed JSON response
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
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": f"{token_type} {access_token}",
        }

    def build_token_info_request_headers(self):
        """
        Builds and returns the headers to be used in the access token request.
        Called by the :meth:`oauthenticator.OAuthenticator.get_token_info`.
        """
        headers = {"Accept": "application/json", "User-Agent": "JupyterHub"}

        if not self.basic_auth:
            b64key = base64.b64encode(
                bytes("{self.client_id}:{self.client_secret}", "utf8")
            )
            headers.update({"Authorization": f'Basic {b64key.decode("utf8")}'})
        return headers

    def user_info_to_username(self, user_info):
        """
        Gets the self.username_claim key's value from the user_info dictionary.
        This is equivalent to the JupyterHub username.

        Should be overridden by the authenticators for which the hub username cannot
        be extracted this way and needs extra processing.

        Args:
            user_info: the dictionary returned by the userdata request

        Returns:
            user_info["self.username_claim"] or raises an error if such value isn't found.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
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
        if self.basic_auth:
            params.update(
                [("client_id", self.client_id), ("client_secret", self.client_secret)]
            )

        params.update(self.token_params)

        return params

    def build_refresh_token_request_params(self, refresh_token):
        """
        Builds the parameters that should be passed to the URL request
        that renew Access Token from Refresh Token.
        Called by the :meth:`oauthenticator.OAuthenticator.refresh_user`.
        """
        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        # the client_id and client_secret should not be included in the access token request params
        # when basic authentication is used
        # ref: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
        if self.basic_auth:
            params.update(
                [("client_id", self.client_id), ("client_secret", self.client_secret)]
            )

        return params

    async def get_token_info(self, handler, params):
        """
        Makes a "POST" request to `self.token_url`, with the parameters received as argument.

        Returns:
            the JSON response to the `token_url` the request.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        url = url_concat(self.token_url, params)

        req = HTTPRequest(
            url,
            method="POST",
            headers=self.build_token_info_request_headers(),
            body=json.dumps(params),
            validate_cert=self.validate_server_cert,
        )

        token_info = await self.fetch(req)

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

        Args:
            token_info: the dictionary returned by the token request (exchanging the OAuth code for an Access Token)

        Returns:
            the JSON response to the `userdata_url` request.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        access_token = token_info["access_token"]
        token_type = token_info["token_type"]

        if not self.userdata_url:
            raise ValueError(
                "authenticator.userdata_url is missing. Please configure it."
            )

        url = url_concat(self.userdata_url, self.userdata_params)
        if self.userdata_token_method == "url":
            url = url_concat(url, dict(access_token=access_token))

        req = HTTPRequest(
            url,
            method="GET",
            headers=self.build_userdata_request_headers(access_token, token_type),
            validate_cert=self.validate_server_cert,
        )

        return await self.fetch(req, "Fetching user info...")

    def get_access_token_creation_date(self, token_info):
        """
        Returns the access token creation date, in seconds (Unix epoch time).

        Example: 1679994631

        Args:
            token_info: the dictionary returned by the token request (exchanging the OAuth code for an Access Token)

        Returns:
            creation_date: a number representing the access token creation date, in seconds (Unix epoch time)

        Called by the :meth:`oauthenticator.OAuthenticator.build_auth_state_dict`
        """
        return token_info.get("created_at", time.time())

    def get_access_token_lifetime(self, token_info):
        """
        Returns the access token lifetime, in seconds.

        Example: 7200

        Args:
            token_info: the dictionary returned by the token request (exchanging the OAuth code for an Access Token)

        Returns:
            lifetime: a number representing the access token lifetime, in seconds

        Called by the :meth:`oauthenticator.OAuthenticator.build_auth_state_dict`
        """
        return token_info.get("expires_in", self.access_token_expiration)

    def build_auth_state_dict(self, token_info, user_info):
        """
        Builds the `auth_state` dict that will be returned by a succesfull `authenticate` method call.

        Args:
            token_info: the dictionary returned by the token request (exchanging the OAuth code for an Access Token)
            user_info: the dictionary returned by the userdata request

        Returns:
            auth_state: a dictionary of auth state that should be persisted with the following keys:
                - "access_token": the access_token
                - "created_at": creation date, in seconds, of the access_token
                - "expires_in": expiration date, in seconds, of the access_token
                - "refresh_token": the refresh_token, if available
                - "id_token": the id_token, if available
                - "scope": the scopes, if available
                - "token_response": the full token_info response
                - self.user_auth_state_key: the full user_info response

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """

        # We know for sure the `access_token` key exists, otherwise we would have errored out already
        access_token = token_info["access_token"]
        created_at = self.get_access_token_creation_date(token_info)
        expires_in = self.get_access_token_lifetime(token_info)

        refresh_token = token_info.get("refresh_token", None)
        id_token = token_info.get("id_token", None)
        scope = token_info.get("scope", "")

        if isinstance(scope, str):
            scope = scope.split(" ")

        return {
            "access_token": access_token,
            "created_at": created_at,
            "expires_in": expires_in,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "scope": scope,
            # Save the full token response
            # These can be used for user provisioning in the Lab/Notebook environment.
            "token_response": token_info,
            # store the whole user model in auth_state too
            self.user_auth_state_key: user_info,
        }

    async def update_auth_model(self, auth_model, **kwargs):
        """
        Updates `auth_model` dict if any fields have changed or additional information is available
        or returns the unchanged `auth_model`.

        Returns the model unchanged by default.

        Should be overridden to take into account changes like group/admin membership.

        Args: auth_model - the auth model dictionary  dict instead, containing:
            - the `name` key holding the username
            - the `auth_state` key, the dictionary of of auth state
                returned by :meth:`oauthenticator.OAuthenticator.build_auth_state_dict`

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        return auth_model

    async def user_is_authorized(self, auth_model):
        """
        Checks if the user that is authenticating should be authorized or not and False otherwise.
        Should be overridden with any relevant logic specific to each oauthenticator.

        Returns True by default.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        return True

    async def authenticate(self, handler, data=None, **kwargs):
        # build the parameters to be used in the request exchanging the oauth code for the access token
        access_token_params = self.build_access_tokens_request_params(handler, data)
        # call the oauth endpoints
        return await self._oauth_call(handler, access_token_params, **kwargs)

    async def refresh_user(self, user, handler=None, **kwargs):
        '''
        Renew the Access Token with a valid Refresh Token
        '''

        auth_state = await user.get_auth_state()
        if not auth_state:
            self.log.info(
                "No auth_state found for user %s refresh, need full authentication",
                user,
            )
            return False

        created_at = auth_state.get('created_at', 0)
        expires_in = auth_state.get('expires_in', 0)
        is_expired = created_at + expires_in - time.time() < 0
        if not is_expired:
            self.log.info(
                "access_token still valid for user %s, skip refresh",
                user,
            )
            return True

        refresh_token_params = self.build_refresh_token_request_params(
            auth_state['refresh_token']
        )
        return await self._oauth_call(handler, refresh_token_params, **kwargs)

    async def _oauth_call(self, handler, params, data=None, **kwargs):
        """
        Common logic shared by authenticate() and refresh_user()
        """

        # exchange the oauth code for an access token and get the JSON with info about it
        token_info = await self.get_token_info(handler, params)
        # use the access_token to get userdata info
        user_info = await self.token_to_user(token_info)
        # extract the username out of the user_info dict
        username = self.user_info_to_username(user_info)

        # check if there any refresh_token in the token_info dict
        refresh_token = token_info.get("refresh_token", None)
        if self.enable_auth_state and not refresh_token:
            self.log.debug(
                "Refresh token was empty, will try to pull refresh_token from previous auth_state"
            )
            refresh_token = await self.get_prev_refresh_token(handler, username)
            if refresh_token:
                token_info["refresh_token"] = refresh_token

        # build the auth model to be persisted if authentication goes right
        auth_model = {
            "name": username,
            "auth_state": self.build_auth_state_dict(token_info, user_info),
        }

        # check if the username that's authenticating should be authorized
        authorized = await self.user_is_authorized(auth_model)
        if not authorized:
            return None

        # update the auth model with any info if available
        return await self.update_auth_model(auth_model, **kwargs)

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
