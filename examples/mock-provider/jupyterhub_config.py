c = get_config()  # noqa

c.JupyterHub.authenticator_class = "generic-oauth"

# assumes oauth provider run with:
# docker run --rm -it -p 127.0.0.1:8080:8080 ghcr.io/navikt/mock-oauth2-server:2.1.1

provider = "http://127.0.0.1:8080/default"
c.GenericOAuthenticator.authorize_url = f"{provider}/authorize"
c.GenericOAuthenticator.token_url = f"{provider}/token"
c.GenericOAuthenticator.userdata_url = f"{provider}/userinfo"
c.GenericOAuthenticator.scope = ["openid", "somescope", "otherscope"]

# these are the defaults. They can be configured at http://localhost:8080/default/debugger
c.GenericOAuthenticator.client_id = "debugger"
c.GenericOAuthenticator.client_secret = "someSecret"

# 'sub' is the first field in the login form
c.GenericOAuthenticator.username_claim = "sub"

c.GenericOAuthenticator.allow_all = True
c.GenericOAuthenticator.admin_users = {"admin"}

# demo boilerplate
c.JupyterHub.default_url = "/hub/home"
c.JupyterHub.spawner_class = "simple"
c.JupyterHub.ip = "127.0.0.1"
