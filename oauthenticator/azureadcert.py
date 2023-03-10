"""
Custom Authenticator to use Azure AD with JupyterHub using passing in 
client assertion and client assertion type instead of client secret. 
This can be used when authenticating using certificates instead of client secrets.
Certificates can be stored in an Azure KeyVault and streamed when the keys are needed
to support encryption of JWT when sending the client assertion to obtain an access token
in return.
"""

import jwt
import urllib
from tornado import web
from tornado.httpclient import HTTPRequest
from traitlets import Any, Unicode, default

from .azuread import AzureAdOAuthenticator

class AzureAdOAuthenticatorWithCertificate(AzureAdOAuthenticator):

    client_assertion_handler = Any(
        config=True,
        help="A callback that returns the client assertion in JWT form"
    )

    def get_client_assertion(self, handler, data):
        return self.client_assertion_handler(handler, data)
    
    def build_access_tokens_request_params_with_certificate(self, handler, data=None):
        code = handler.get_argument("code")

        if not code:
            raise web.HTTPError(400, "Authentication Cancelled.")

        params = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.get_callback_url(handler),
            "data": data,
        }

        # Client assertions can be used anywhere a client secret would be used.
        # Client secret can be replaced with client_assertion and client_assertion_type parameters.
        # ref: https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials#using-a-client-assertion
        params.update(
            [("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
             ("client_assertion", self.get_client_assertion(handler, data)),
             ("client_id", self.client_id),
             ("scope", f'{self.client_id}/.default')]
        )

        params.update(self.token_params)

        return params
    
    token_url = Unicode(
        config=True,
        help="""The url retrieving an access token at the completion of oauth""",
    )
        
    @default("token_url")
    def _token_url_default(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

    authorize_url = Unicode(
        config=True, help="""The authenticate url for initiating oauth"""
    )

    @default("authorize_url")
    def _authorize_url_default(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"

    async def token_to_user(self, token_info):
        access_token = token_info['access_token']

        decoded = jwt.decode(
            access_token,
            options={"verify_signature": False},
            audience=self.client_id,
        )

        # validate client id, tenant_id and appidacr == 2 to check if authenticated with certificate
        if decoded['aud'] == self.client_id and \
            decoded['tid'] == self.tenant_id and \
            decoded['appidacr'] == '2' and \
            decoded['appid'] == self.client_id:
             return decoded
        else:
             return {}

    def build_token_info_request_headers(self):
        """
        Builds and returns the headers to be used in the access token request.
        Called by the :meth:`oauthenticator.OAuthenticator.get_token_info`.
        Reference Link: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return headers
    
    async def get_token_info_with_certificate(self, handler, params):
        """
        Makes a "POST" request to `self.token_url`, with the parameters received as argument.

        Returns:
            the JSON response to the `token_url` the request.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        url = self.token_url

        request_headers = self.build_token_info_request_headers()

        encodedbody=urllib.parse.urlencode(params)

        req = HTTPRequest(
            url,
            method="POST",
            headers=request_headers,
            body=encodedbody,
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

    async def authenticate(self, handler, data=None, **kwargs):
        # build the parameters to be used in the request exchanging the oauth code for the access token
        access_token_params = self.build_access_tokens_request_params_with_certificate(handler, data)
        # exchange the oauth code for an access token and get the JSON with info about it
        token_info = await self.get_token_info_with_certificate(handler, access_token_params)
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
