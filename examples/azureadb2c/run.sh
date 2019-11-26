export AAD_LOGIN_SERVICE_NAME='Azure AD B2C'
export OAUTH_ACCESS_TOKEN_URL='https://login.microsoftonline.com/dnvglb2cprod.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1A_SignInWithADFSIdp_EmailAsString'
export OAUTH_AUTHORIZE_URL='https://login.microsoftonline.com/dnvglb2cprod.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_SignInWithADFSIdp_EmailAsString'
export OAUTH_SCOPE='openid https://dnvglb2cprod.onmicrosoft.com/83054ebf-1d7b-43f5-82ad-b2bde84d7b75/user_impersonation'

jupyterhub -f ./config.py --log-level=DEBUG
