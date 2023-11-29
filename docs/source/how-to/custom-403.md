# Custom login errors

When a user is recognized by an identity provider but isn't allowed to sign in,
the following message is shown by default.

```
Sorry, you are not currently authorized to use this hub. Please contact the hub administrator.
```

You can configure a custom error message like this:

```python
c.OAuthenticator.custom_403_message = "Your message for the user"
```

You can also show a customized 403 HTML page by creating a [custom HTML
template], and configuring JupyterHub to find it.

An example of such custom 403 HTML template can be found in this project's
[examples/templates directory]

```python
c.JupyterHub.template_paths = ["examples/templates"]
```

[custom HTML template]: https://jupyterhub.readthedocs.io/en/stable/reference/templates.html
[examples/templates directory]: https://github.com/jupyterhub/oauthenticator/tree/main/examples/templates
