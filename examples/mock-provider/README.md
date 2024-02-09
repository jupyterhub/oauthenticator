# Generic OAuth with mock provider

This example uses [mock-oauth2-server][] to launch a standalone local OAuth2 provider and configures GenericOAuthenticator to use it.

mock-auth2-server implements OpenID Connect (OIDC), and can be used to test GenericOAuthenticator configurations for use with OIDC providers without needing to register your application with a real OAuth provider.

[mock-oauth2-server]: https://github.com/navikt/mock-oauth2-server

To launch the oauth provider in a container:

```
docker run --rm -it -p 127.0.0.1:8080:8080 ghcr.io/navikt/mock-oauth2-server:2.1.1
```

Then launch JupyterHub:

```
jupyterhub
```

When you login, you will be presented with a form allowing you to specify the username, and (optionally) any additional fields that should be present in the `userinfo` response.
