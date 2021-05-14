"""
Example OAuthenticator to use with My Service
"""
import json

from jupyterhub.auth import LocalAuthenticator
from tornado.auth import OAuth2Mixin
from tornado.httpclient import AsyncHTTPClient
from tornado.httpclient import HTTPError
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat

from oauthenticator.oauth2 import OAuthenticator
from oauthenticator.oauth2 import OAuthLoginHandler


class MyServiceMixin(OAuth2Mixin):
    # authorize is the URL users are redirected to to authorize your service
    _OAUTH_AUTHORIZE_URL = "https://myservice.biz/login/oauth/authorize"
    # token is the URL JupyterHub accesses to finish the OAuth process
    _OAUTH_ACCESS_TOKEN_URL = "https://myservice.biz/login/oauth/access_token"


class MyServiceLoginHandler(OAuthLoginHandler, MyServiceMixin):
    pass


class GitHubOAuthenticator(OAuthenticator):

    # login_service is the text displayed on the "Login with..." button
    login_service = "My Service"

    login_handler = MyServiceLoginHandler

    async def authenticate(self, handler, data=None):
        """We set up auth_state based on additional GitHub info if we
        receive it.
        """
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for an Access Token
        # this is the TOKEN URL in your provider

        params = dict(
            client_id=self.client_id, client_secret=self.client_secret, code=code
        )

        url = url_concat("https://myservice.biz/login/oauth/access_token", params)

        req = HTTPRequest(
            url, method="POST", headers={"Accept": "application/json"}, body=''
        )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if 'access_token' in resp_json:
            access_token = resp_json['access_token']
        elif 'error_description' in resp_json:
            raise HTTPError(
                403,
                "An access token was not returned: {}".format(
                    resp_json['error_description']
                ),
            )
        else:
            raise HTTPError(500, "Bad response: {}".format(resp))

        # Determine who the logged in user is
        # by using the new access token to make a request
        # check with your OAuth provider for this URL.
        # it could also be in the response to the token request,
        # making this request unnecessary.

        req = HTTPRequest(
            "https://myservice.biz/api/user",
            method="GET",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        # check the documentation for what field contains a unique username
        # it might not be the 'username'!
        username = resp_json["username"]

        if not username:
            # return None means that no user is authenticated
            # and login has failed
            return None

        # here we can add additional checks such as against team allowed lists
        # if the OAuth provider has such a concept

        # 'name' is the JupyterHub username
        user_info = {"name": username}

        # We can also persist auth state,
        # which is information encrypted in the Jupyter database
        # and can be passed to the Spawner for e.g. authenticated data access
        # these fields are up to you, and not interpreted by JupyterHub
        # see Authenticator.pre_spawn_start for how to use this information
        user_info["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        auth_state['auth_reply'] = resp_json

        return user_info


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
