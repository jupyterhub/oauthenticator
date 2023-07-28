(tutorials:general-setup)=

# General setup

This project provides _JupyterHub Authenticator classes_. A JupyterHub
authenticator class helps JupyterHub to delegate the task of deciding who a user
is (authentication) and if the user should be granted access to sign in
(authorization).

This section describes general steps to setup a JupyterHub to use one of these
projects' authenticator classes.

1. Decide on an _identity provider_

   As an example, if you want users to login with their GitHub accounts, then
   GitHub is the identity provider.

2. Register an _OAuth2 application_ with the identity provider

   The identity provider needs to allow you to register an OAuth2 application,
   and you can typically search the internet for guides on doing this for the
   identity provider.

   When doing this, you should at some point declare a _redirect url_. This
   should be `https://[your-domain]/hub/oauth_callback` where you replace
   `[your-domain]`.

   After this step, you should have a _client id_, a _client secret_.

   [redirect url]: https://www.oauth.com/oauth2-servers/redirect-uris/

3. Configure JupyterHub to use one compatible authenticator class

   The authenticator class can be the general purpose `GenericOAuthenticator`
   class, or a specialized authenticator class like `GitHubOAuthentator`.

   ```python
   # code for a jupyterhub_config.py file...
   c.JupyterHub.authenticator_class = "github"
   ```

4. Configure the authenticator base class

   Based on the information from step 2, configure the following.

   ```python
   # code for a jupyterhub_config.py file...
   c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
   c.OAuthenticator.client_id = "[your oauth2 application id]"
   c.OAuthenticator.client_secret = "[your oauth2 application secret]"
   ```

5. Configure the authenticator class further

   By default, no users will be allowed access. At this point you should
   configure what users should be granted access. The OAuthenticator base class
   provides the following config you can read more about in the configuration
   reference.

   - {attr}`.OAuthenticator.allow_all`
   - {attr}`.OAuthenticator.allow_existing_users`
   - {attr}`.OAuthenticator.allowed_users`
   - {attr}`.OAuthenticator.admin_users`

   Your authenticator class may have unique config, so in the end it can look
   something like this:

   ```
   c.JupyterHub.authenticator_class = "github"

   c.OAuthenticator.oauth_callback_url = "https://my-jupyterhub.prg/hub/oauth_callback"
   c.OAuthenticator.client_id = "1234-5678-9012-3456"
   c.OAuthenticator.client_secret = "abcd-edfg-ijkl-mnop"

   c.OAuthenticator.allow_existing_users = True
   c.OAuthenticator.allowed_users = {"github-user-1", "github-user-2"}
   c.OAuthenticator.admin_users = {"github-user-3"}

   c.GitHubOAuthenticator.allowed_organizations = {"github-organization-1"}
   c.GitHubOAuthenticator.scope = ["user:email", "read:org"]
   ```
