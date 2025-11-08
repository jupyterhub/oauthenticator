# Configuration file for Jupyter Hub

import os
import sys
from oauthenticator.azuread import AzureAdOAuthenticator

join = os.path.join

here = os.path.dirname(__file__)
root = os.environ.get('OAUTHENTICATOR_DIR', here)
sys.path.insert(0, root)

c = get_config()

c.JupyterHub.log_level = 10
c.JupyterHub.admin_users = admin = set()

with open(join(root, 'admins')) as f:
    for line in f:
        if not line:
            continue
        parts = line.split()
        name = parts[0]
        admin.add(name)

c.JupyterHub.authenticator_class = AzureAdOAuthenticator
c.JupyterHub.shutdown_on_logout = True

# Configure Azure AD specific settings
c.AzureAdOAuthenticator.tenant_id = os.environ.get('AAD_TENANT_ID')
c.AzureAdOAuthenticator.client_id = os.environ.get('AAD_APP_CLIENT_ID')
c.AzureAdOAuthenticator.client_secret = os.environ.get('AAD_APP_CLIENT_SECRET')


# Define the OAuth callback URL, matching your Azure AD app registration's redirect URI
c.AzureAdOAuthenticator.oauth_callback_url = 'https://[your-jupyterhub-domain]/hub/oauth_callback'

# Define the scopes you are requesting from Azure AD
c.AzureAdOAuthenticator.scope = ['openid', 'email', 'profile']

# Optional: Set log level for debugging
c.Application.log_level = 'DEBUG'

# Optional: Configure admin users (replace with actual usernames)
# c.JupyterHub.admin_users = {'admin_user1', 'admin_user2'} 