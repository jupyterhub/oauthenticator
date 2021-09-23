"""
Custom Authenticator to use multiple OAuth providers with JupyterHub

Example of configuration:

    from oauthenticator.github import GitHubOAuthenticator
    from oauthenticator.google import GoogleOAuthenticator

    c.MultiOAuthenticator.authenticators = [
        (GitHubOAuthenticator, '/github', {
            'client_id': 'xxxx',
            'client_secret': 'xxxx',
            'oauth_callback_url': 'http://example.com/hub/github/oauth_callback'
        }),
        (GoogleOAuthenticator, '/google', {
            'client_id': 'xxxx',
            'client_secret': 'xxxx',
            'oauth_callback_url': 'http://example.com/hub/google/oauth_callback'
        })
    ]

    c.JupyterHub.authenticator_class = 'oauthenticator.multioauthenticator.MultiOAuthenticator'

The same Authenticator class can be used several to support different providers.

"""
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join
from traitlets import List


class MultiOAuthenticator(Authenticator):
    """Wrapper class that allows to use more than one authentication provider
    for JupyterHub"""

    authenticators = List(help="The subauthenticators to use", config=True)

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self._authenticators = []
        for (
            authenticator_klass,
            url_scope,
            authenticator_configuration,
        ) in self.authenticators:
            configuration = self.trait_values()
            # Remove this one as it will overwrite the value if the authenticator_klass
            # makes it configurable and the default value is used (take a look at
            # GoogleOAuthenticator for example).
            configuration.pop("login_service")
            configuration.update(authenticator_configuration)
            self._authenticators.append(
                {
                    "instance": authenticator_klass(**configuration),
                    "url_scope": url_scope,
                }
            )

    def get_custom_html(self, base_url):
        """Re-implementation generating one login button per configured authenticator"""

        html = []
        for authenticator in self._authenticators:
            login_service = authenticator["instance"].login_service
            url = url_path_join(base_url, authenticator["url_scope"], "oauth_login")

            html.append(
                f"""
                <div class="service-login">
                  <a role="button" class='btn btn-jupyter btn-lg' href='{url}'>
                    Sign in with {login_service}
                  </a>
                </div>
                """
            )
        return "\n".join(html)

    def get_handlers(self, app):
        """Re-implementation that will return the handlers for all configured
        authenticators"""

        routes = []
        for _authenticator in self._authenticators:
            for path, handler in _authenticator["instance"].get_handlers(app):

                class WrapperHandler(handler):
                    """'Real' handler configured for each authenticator. This allows
                    to reuse the same authenticator class configured for different
                    services (for example GitLab.com, gitlab.example.com)
                    """

                    authenticator = _authenticator["instance"]

                routes.append((f'{_authenticator["url_scope"]}{path}', WrapperHandler))
        return routes
