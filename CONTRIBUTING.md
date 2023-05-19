# Contributing

Welcome! As a [Jupyter](https://jupyter.org) project, we follow the [Jupyter contributor guide](https://jupyter.readthedocs.io/en/latest/contributor/content-contributor.html)
and [Code of Conduct](https://github.com/jupyter/governance/blob/HEAD/conduct/code_of_conduct.md).

To set up a development environment for this repository:

1. Clone this repository:

   ```
   git clone https://github.com/jupyterhub/oauthenticator
   ```

2. Do a development install with pip:

   ```
   cd oauthenticator
   pip install -e ".[test]"
   ```

3. Install pre-commit hooks that checks formatting before commits are made.

   ```
   pip install pre-commit
   pre-commit install --install-hooks
   ```

4. Run tests

   ```
   pytest
   ```

Note: OAuthenticator _is not_ accepting pull requests adding new OAuth providers.
See the documentation for how to use GenericOAuthenticator with your provider
or to write your own OAuthenticator class for your provider.

Feel free to ask for help [on the Jupyter forum](https://discourse.jupyter.org)
