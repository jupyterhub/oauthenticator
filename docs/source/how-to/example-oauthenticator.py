"""
Example OAuthenticator to use with My Service
"""
from jupyterhub.auth import LocalAuthenticator

from oauthenticator.oauth2 import OAuthenticator, OAuthLoginHandler


class MyServiceLoginHandler(OAuthLoginHandler):
    pass


class MyServiceOAuthenticator(OAuthenticator):
    # login_service is the text displayed on the "Login with..." button
    login_service = "My Service"

    login_handler = MyServiceLoginHandler

    # the URL users are redirected to logout
    logout_redirect_url = "https://myservice.biz/logout"
    # the URL users are redirected to authorize your service
    authorize_url = "https://myservice.biz/login/oauth/authorize"
    # the URL JupyterHub accesses to finish the OAuth process
    token_url = "https://myservice.biz/login/oauth/access_token"
    # the URL for retrieving user data with a completed access token
    userdata_url = "https://myservice.biz/login/oauth/userinfo"

    # The name of the user key expected to be present in `auth_state`
    # Ex: github_user, auth0_user, google user, etc.
    # Defaults to oauth_user.
    user_auth_state_key = "oauth_user"

    # Build the parameters to be used in the request exchanging the OAuth code for the Access Token.
    # params = {
    #     "code": code,
    #     "grant_type": "authorization_code",
    #     "redirect_uri": self.get_callback_url(handler),
    #     "data": data,
    # }
    # self.client_id and self.client_secret are also included in the params when self.basic_auth == False
    # Only override this method if you'd like other params passed
    # or if any additional processing of this params is needed.
    def build_access_tokens_request_params(self, handler, data=None):
        pass

    # Exchange the OAuth code for an Access Token.
    # Only override this method if your Service needs additional services in place,
    # in order to send the request (see `MWOAuthenticator``)
    # or you'd like additional processing of the HTTP status codes.
    async def get_token_info(self, handler, params):
        pass

    # Use the access_token to get userdata info.
    # Determine who the logged in user is
    # by using the new access token to make a request to self.userdata_url
    # check with your OAuth provider for this URL.
    # Only override this method if your Service needs additional services in place,
    # in order to send the request (see `MWOAuthenticator``)
    # or you'd like additional processing of the HTTP status codes.
    async def token_to_user(self, token_info):
        pass

    # Extract the username out of the user_info dict.
    # Gets the self.username_claim key's value from the user_info dictionary.
    # This will be the JupyterHub username.
    # Should be overridden by the authenticators for which the hub username cannot
    # be extracted this way and needs extra processing.
    def user_info_to_username(self, user_info):
        pass

    # We can also persist auth state, which is information encrypted in the Jupyter database
    # and can be passed to the Spawner for e.g. authenticated data access/
    # Builds the `auth_state` dict that will be returned by a successful `authenticate` method call.
    # Returns:
    # auth_state: a dictionary of auth state that should be persisted with the following keys:
    #     - "access_token": the access_token
    #     - "refresh_token": the refresh_token, if available
    #     - "id_token": the id_token, if available
    #     - "scope": the scopes, if available
    #     - "token_response": the full token_info response
    #     - self.user_auth_state_key: the full user_info response
    # Override this if you want more or less information to be returned after a successful `authenticate` method call.
    # These fields are up to you, and not interpreted by JupyterHub. See Authenticator.pre_spawn_start for how to use this information
    def build_auth_state_dict(self, token_info, user_info):
        pass

    # Updates `auth_model` dict if any fields have changed or additional information is available
    # or returns the unchanged `auth_model`.
    # Returns the model unchanged by default.
    # Should be overridden to take into account additional checks such as against group/admin/team membership.
    # if the OAuth provider has such a concept
    async def update_auth_model(self, username, auth_model):
        pass


class LocalMyServiceOAuthenticator(LocalAuthenticator, MyServiceOAuthenticator):
    """A version that mixes in local system user creation"""
