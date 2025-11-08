import os

from oauthenticator.azuread import AzureAdOAuthenticator

c.JupyterHub.authenticator_class = AzureAdOAuthenticator

c.Application.log_level = 'DEBUG'

c.AzureAdOAuthenticator.tenant_id = os.environ.get('AAD_TENANT_ID')

c.AzureAdOAuthenticator.oauth_callback_url = 'http://{your-domain}/hub/oauth_callback'
c.AzureAdOAuthenticator.client_id = '{AAD-APP-CLIENT-ID}'
c.AzureAdOAuthenticator.client_secret = '{AAD-APP-CLIENT-SECRET}'

# if the user's name returned by Azure isn't acceptable to JupyterHub then we can use an alternate field,
# uncomment the line below to use 'unique_name' rather than the default 'name'. Consult the Azure
# documentation for other field names.
# c.AzureAdOAuthenticator.username_claim = 'unique_name'

# if you are using a different cloud then Azure portal (global service) you will need to provide
# the graph url. By default it will use the https://login.microsoftonline.com


# c.AzureAdOAuthenticator.graph_url = os.environ.get('AAD_GRAPH_URL')