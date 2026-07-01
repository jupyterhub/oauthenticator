"""
Custom Authenticator to use multiple OAuth providers with JupyterHub

Example of configuration:

    from oauthenticator.github import GitHubOAuthenticator
    from oauthenticator.google import GoogleOAuthenticator

    c.MultiAuthenticator.authenticators = [
        (GitHubOAuthenticator, '/github', {
            'client_id': 'xxxx',
            'client_secret': 'xxxx',
            'oauth_callback_url': 'http://example.com/hub/github/oauth_callback'
        }),
        (GoogleOAuthenticator, '/google', {
            'client_id': 'xxxx',
            'client_secret': 'xxxx',
            'oauth_callback_url': 'http://example.com/hub/google/oauth_callback'
        }),
        (PAMAuthenticator, "/pam", {"service_name": "PAM"}),
    ]

    c.JupyterHub.authenticator_class = 'oauthenticator.MultiAuthenticator.MultiAuthenticator'

The same Authenticator class can be used several to support different providers.

"""
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join
from traitlets import List


class URLScopeMixin(object):
    """Mixin class that adds the"""

    scope = ""

    def login_url(self, base_url):
        return super().login_url(url_path_join(base_url, self.scope))

    def logout_url(self, base_url):
        return super().logout_url(url_path_join(base_url, self.scope))

    def get_handlers(self, app):
        handlers = super().get_handlers(app)
        return [
            (url_path_join(self.scope, path), handler) for path, handler in handlers
        ]


class MultiAuthenticator(Authenticator):
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

            class WrapperAuthenticator(URLScopeMixin, authenticator_klass):
                scope = url_scope

            service_name = authenticator_configuration.pop("service_name", None)
            configuration.update(authenticator_configuration)

            authenticator = WrapperAuthenticator(**configuration)

            if service_name:
                authenticator.service_name = service_name

            self._authenticators.append(authenticator)

    def get_custom_html(self, base_url):
        """Re-implementation generating one login button per configured authenticator"""

        html = []
        for authenticator in self._authenticators:
            if hasattr(authenticator, "service_name"):
                login_service = getattr(authenticator, "service_name")
            else:
                login_service = authenticator.login_service

            url = authenticator.login_url(base_url)

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
            for path, handler in _authenticator.get_handlers(app):

                class WrapperHandler(handler):
                    """'Real' handler configured for each authenticator. This allows
                    to reuse the same authenticator class configured for different
                    services (for example GitLab.com, gitlab.example.com)
                    """

                    authenticator = _authenticator

                routes.append((path, WrapperHandler))
        return routes
