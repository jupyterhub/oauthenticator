# OkpyAuthenticator

Okpy + JupyterHub Authentication = OkpyAuthenticator!


This repo adds OkpyAuthenticator into JupyterHub's [OAuthenticator](https://github.com/jupyterhub/oauthenticator).


[Okpy](https://github.com/Cal-CS-61A-Staff/ok-client) is an auto-grading tool that
is widely used in UC Berkeley EECS and Data Science courses. This authenticator
enhances its support for Jupyter Notebook by enabling students to authenticate with
the [Hub](http://datahub.berkeley.edu/hub/home) first and saving relevant user states
to the `env`.


# Configuration

If you want to authenticate your Hub using OkpyAuthenticator, you need to specify
the authenticator class in your `jupyterhub_config.py` file:

```
c.JupyterHub.authenticator_class = 'oauthenticator.OkpyOAuthenticator'
```

You also need to configure the following parameters:
```
c.OkpyOAuthenticator.client_id =  #client_id recognized by Okpy
c.OkpyOAuthenticator.client_secret = #the associated client secret
c.OkpyOAuthenticator.oauth_callback_url = #callback url to the Hub

c.Spawner.environment = {
    'OKPY_REFRESH_TOKEN': lambda spawner: spawner.user.auth_state['refresh_token'],
    'OKPY_ACCESS_TOKEN': lambda spawner: spawner.user.auth_state['access_token'],
    'OKPY_EXPIRES_IN': lambda spawner: str(spawner.user.auth_state['expires_in'])
}

```
