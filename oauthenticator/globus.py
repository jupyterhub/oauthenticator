"""
Custom Authenticator to use Globus OAuth2 with JupyterHub
"""
import os
import pickle
import json
import base64
import urllib

from tornado.web import HTTPError
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from traitlets import List, Unicode, Bool, default

from jupyterhub.handlers import LogoutHandler
from jupyterhub.utils import url_path_join
from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthenticator


class GlobusLogoutHandler(LogoutHandler):
    """
    Handle custom logout URLs and token revocation. If a custom logout url
    is specified, the 'logout' button will log the user out of that identity
    provider in addition to clearing the session with Jupyterhub, otherwise
    only the Jupyterhub session is cleared.
    """

    async def get(self):
        # Ensure self.handle_logout() is called before self.default_handle_logout()
        # If default_handle_logout() is called first, the user session is popped and
        # it's not longer possible to call get_auth_state() to revoke tokens.
        # See https://github.com/jupyterhub/jupyterhub/blob/master/jupyterhub/handlers/login.py  # noqa
        await self.handle_logout()
        await self.default_handle_logout()
        if self.authenticator.logout_redirect_url:
            # super().get() will attempt to render a logout page. Make sure we
            # return after the redirect to avoid exceptions.
            self.redirect(self.authenticator.logout_redirect_url)
            return
        await super().get()

    async def handle_logout(self):
        """Overridden method for custom logout functionality. Should be called by
        Jupyterhub on logout just before destroying the users session to log them out."""
        if self.current_user and self.authenticator.revoke_tokens_on_logout:
            await self.clear_tokens(self.current_user)

    async def clear_tokens(self, user):
        """Revoke and clear user tokens from the database"""
        state = await user.get_auth_state()
        if state:
            await self.authenticator.revoke_service_tokens(state.get('tokens'))
            self.log.info(
                'Logout: Revoked tokens for user "{}" services: {}'.format(
                    user.name, ','.join(state['tokens'].keys())
                )
            )
            state['tokens'] = {}
            await user.save_auth_state(state)


class GlobusOAuthenticator(OAuthenticator):
    """The Globus OAuthenticator handles both authorization and passing
    transfer tokens to the spawner. """

    login_service = 'Globus'
    logout_handler = GlobusLogoutHandler

    @default("userdata_url")
    def _userdata_url_default(self):
        return "https://auth.globus.org/v2/oauth2/userinfo"

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://auth.globus.org/v2/oauth2/authorize"

    @default("revocation_url")
    def _revocation_url_default(self):
        return "https://auth.globus.org/v2/oauth2/token/revoke"

    revocation_url = Unicode(
        help="Globus URL to revoke live tokens."
    ).tag(config=True)

    @default("token_url")
    def _token_url_default(self):
        return "https://auth.globus.org/v2/oauth2/token"

    identity_provider = Unicode(
        help="""Restrict which institution a user
    can use to login (GlobusID, University of Hogwarts, etc.). This should
    be set in the app at developers.globus.org, but this acts as an additional
    check to prevent unnecessary account creation."""
    ).tag(config=True)

    def _identity_provider_default(self):
        return os.getenv('IDENTITY_PROVIDER', '')

    exclude_tokens = List(
        help="""Exclude tokens from being passed into user environments
        when they start notebooks, Terminals, etc."""
    ).tag(config=True)

    def _exclude_tokens_default(self):
        return ['auth.globus.org']

    def _scope_default(self):
        return [
            'openid',
            'profile',
            'urn:globus:auth:scope:transfer.api.globus.org:all',
        ]

    globus_local_endpoint = Unicode(
        help="""If Jupyterhub is also a Globus
    endpoint, its endpoint id can be specified here."""
    ).tag(config=True)

    def _globus_local_endpoint_default(self):
        return os.getenv('GLOBUS_LOCAL_ENDPOINT', '')

    logout_redirect_url = Unicode(help="""URL for logging out.""").tag(config=True)

    def _logout_redirect_url_default(self):
        return os.getenv('LOGOUT_REDIRECT_URL', '')

    revoke_tokens_on_logout = Bool(
        help="""Revoke tokens so they cannot be used again. Single-user servers
        MUST be restarted after logout in order to get a fresh working set of
        tokens."""
    ).tag(config=True)

    def _revoke_tokens_on_logout_default(self):
        return False

    async def pre_spawn_start(self, user, spawner):
        """Add tokens to the spawner whenever the spawner starts a notebook.
        This will allow users to create a transfer client:
        globus-sdk-python.readthedocs.io/en/stable/tutorial/#tutorial-step4
        """
        spawner.environment['GLOBUS_LOCAL_ENDPOINT'] = self.globus_local_endpoint
        state = await user.get_auth_state()
        if state:
            globus_data = base64.b64encode(pickle.dumps(state))
            spawner.environment['GLOBUS_DATA'] = globus_data.decode('utf-8')

    async def authenticate(self, handler, data=None):
        """
        Authenticate with globus.org. Usernames (and therefore Jupyterhub
        accounts) will correspond to a Globus User ID, so foouser@globusid.org
        will have the 'foouser' account in Jupyterhub.
        """
        # Complete login and exchange the code for tokens.
        http_client = AsyncHTTPClient()
        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=handler.get_argument("code"),
            grant_type='authorization_code',
        )
        req = HTTPRequest(self.token_url, method="POST",
            headers=self.get_client_credential_headers(),
            body=urllib.parse.urlencode(params),
        )
        token_response = await http_client.fetch(req)
        token_json = json.loads(token_response.body.decode('utf8', 'replace'))

        # Fetch user info at Globus's oauth2/userinfo/ HTTP endpoint to get the username
        user_headers = self.get_default_headers()
        user_headers['Authorization'] = 'Bearer {}'.format(token_json['access_token'])
        req = HTTPRequest(self.userdata_url, method='GET', headers=user_headers)
        user_resp = await http_client.fetch(req)
        user_json = json.loads(user_resp.body.decode('utf8', 'replace'))
        # It's possible for identity provider domains to be namespaced
        # https://docs.globus.org/api/auth/specification/#identity_provider_namespaces # noqa
        username, domain = user_json.get('preferred_username').split('@', 1)
        if self.identity_provider and domain != self.identity_provider:
            raise HTTPError(
                403,
                'This site is restricted to {} accounts. Please link your {}'
                ' account at {}.'.format(
                    self.identity_provider,
                    self.identity_provider,
                    'globus.org/app/account',
                ),
            )

        # Each token should have these attributes. Resource server is optional,
        # and likely won't be present.
        token_attrs = ['expires_in', 'resource_server', 'scope',
                       'token_type', 'refresh_token', 'access_token']
        # The Auth Token is a bit special, it comes back at the top level with the
        # id token. The id token has some useful information in it, but nothing that
        # can't be retrieved with an Auth token.
        # Repackage the Auth token into a dict that looks like the other tokens
        auth_token_dict = {attr_name: token_json.get(attr_name) for attr_name in token_attrs}
        # Make sure only the essentials make it into tokens. Other items, such as 'state' are
        # not needed after authentication and can be discarded.
        other_tokens = [{attr_name: token_dict.get(attr_name) for attr_name in token_attrs}
                        for token_dict in token_json['other_tokens']]
        tokens = other_tokens + [auth_token_dict]
        # historically, tokens have been organized by resource server for convenience.
        # If multiple scopes are requested from the same resource server, they will be
        # combined into a single token from Globus Auth.
        by_resource_server = {
                    token_dict['resource_server']: token_dict
                    for token_dict in tokens
                    if token_dict['resource_server'] not in self.exclude_tokens
                }
        return {
            'name': username,
            'auth_state': {
                'client_id': self.client_id,
                'tokens': by_resource_server,
            },
        }

    def get_default_headers(self):
        return {"Accept": "application/json", "User-Agent": "JupyterHub"}

    def get_client_credential_headers(self):
        headers = self.get_default_headers()
        b64key = base64.b64encode(
            bytes("{}:{}".format(self.client_id, self.client_secret), "utf8")
        )
        headers["Authorization"] = "Basic {}".format(b64key.decode("utf8"))
        return headers

    async def revoke_service_tokens(self, services):
        """Revoke live Globus access and refresh tokens. Revoking inert or
        non-existent tokens does nothing. Services are defined by dicts
        returned by tokens.by_resource_server, for example:
        services = { 'transfer.api.globus.org': {'access_token': 'token'}, ...
            <Additional services>...
        }
        """
        access_tokens = [token_dict.get('access_token') for token_dict in services.values()]
        refresh_tokens = [token_dict.get('refresh_token') for token_dict in services.values()]
        all_tokens = [tok for tok in access_tokens + refresh_tokens if tok is not None]
        http_client = AsyncHTTPClient()
        for token in all_tokens:
            req = HTTPRequest(self.revocation_url,
                              method="POST",
                              headers=self.get_client_credential_headers(),
                              body=urllib.parse.urlencode({'token': token}),
                              )
            await http_client.fetch(req)

    def logout_url(self, base_url):
        return url_path_join(base_url, 'logout')

    def get_handlers(self, app):
        return super().get_handlers(app) + [(r'/logout', self.logout_handler)]


class LocalGlobusOAuthenticator(LocalAuthenticator, GlobusOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
