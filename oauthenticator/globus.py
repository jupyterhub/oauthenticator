"""
Custom Authenticator to use Globus OAuth2 with JupyterHub
"""
import pwd
from tornado import gen, web
from tornado.auth import OAuth2Mixin
from tornado.concurrent import return_future
from tornado.web import HTTPError
from .oauth2 import OAuthLoginHandler, OAuthenticator

try:
    import globus_sdk
except:
    raise ImportError("Trying to use the Globus Auth "
                      "authenticator, but globus_sdk "
                      "is not installed")


class GlobusMixin(OAuth2Mixin):
    """
    Overriding the tornado function because
    globus provides it's own method to assemble the
    authorize url
    """
    @return_future
    def authorize_redirect(self, client=None, callback=None):
        self.redirect(client.oauth2_get_authorize_url())
        callback()


class GlobusLoginHandler(OAuthLoginHandler, GlobusMixin):
    def get(self):
        # Doing the scope weirdness for the globus_sdk
        scopes = ['openid', 'profile', 'email',
                  'urn:globus:auth:scope:auth.globus.org:view_identities']
        scope_string = (' ').join(scopes)
        redirect_uri = self.authenticator.get_callback_url(self)
        client = self.authenticator.globus_portal_client()
        client.oauth2_start_flow(
            redirect_uri,
            requested_scopes=scope_string,
            refresh_tokens=True)
        self.log.info('globus redirect: %r', redirect_uri)
        self.authorize_redirect(client)


class GlobusOAuthenticator(OAuthenticator):

    login_service = "Globus"
    login_handler = GlobusLoginHandler

    def globus_portal_client(self):
        """
        Create an Globus Auth ConfidentialAppAuthClient
        Need a ConfidentialAppAuthClient because the NativeAppClient
        would require user input, i.e. c/p the token from the website
        somewhere, which we wont do... for now.
        """
        return globus_sdk.ConfidentialAppAuthClient(
            self.client_id,
            self.client_secret)

    @gen.coroutine
    def authenticate(self, handler, data=None):
        """
        Overwritting the authenticate method with a Globus Auth specific one
        """
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        scopes = ['openid', 'profile', 'email',
                  'urn:globus:auth:scope:auth.globus.org:view_identities']
        scope_string = (' ').join(scopes)
        redirect_uri = self.get_callback_url(self)
        client = self.globus_portal_client()
        client.oauth2_start_flow(
            redirect_uri,
            requested_scopes=scope_string,
            refresh_tokens=True)
        # Doing the code for token for id_token exchange
        tokens = client.oauth2_exchange_code_for_tokens(code)
        id_token = tokens.decode_id_token(client)
        username = id_token.get('preferred_username')
        if not username.endswith('@globusid.org'):
            raise HTTPError(403, ("You are not signed in "
                                  "to your {} account.".format("Globus ID")))
        # Need to return a username without the "email" ending
        username = username.split('@')[0]
        return username

    def get_callback_url(self, handler=None):
        """
        Getting the configured callback url
        """
        if self.oauth_callback_url is None:
            raise HTTPError(500, ("No callback url provided. "
                                  "Please configure by adding "
                                  "c.GlobusOAuthenticator.oauth_callback_url "
                                  "to the config"))
        return self.oauth_callback_url
