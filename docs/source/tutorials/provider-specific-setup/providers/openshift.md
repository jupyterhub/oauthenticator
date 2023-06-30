# OpenShift Setup

In case you have an OpenShift deployment with OAuth properly configured
(see the following sections for a quick reference), you should set the
client ID and secret by the environment variables `OAUTH_CLIENT_ID`,
`OAUTH_CLIENT_SECRET` and `OAUTH_CALLBACK_URL`.

Prior to OpenShift 4.0, the OAuth provider and REST API URL endpoints
can be specified by setting the single environment variable
`OPENSHIFT_URL`. From OpenShift 4.0 onwards, these two endpoints are
on different hosts. You need to set `OPENSHIFT_AUTH_API_URL` to the
OAuth provider URL, and `OPENSHIFT_REST_API_URL` to the REST API URL
endpoint.

The `OAUTH_CALLBACK_URL` should match
`http[s]://[your-app-route]/hub/oauth_callback`

## Global OAuth (admin)

As a cluster admin, you can create a global [OAuth
client](https://docs.okd.io/latest/authentication/configuring-oauth-clients.html)
in your OpenShift cluster creating a new OAuthClient object using the
API:

```bash
oc create -f - <<EOF
apiVersion: v1
kind: OAuthClient
metadata:
   name: <OAUTH_CLIENT_ID>
redirectURIs:
- <OUAUTH_CALLBACK_URL>
secret: <OAUTH_SECRET>
EOF
```

## Service Accounts as OAuth Clients

As a project member, you can use the [Service Accounts as OAuth Clients](https://docs.openshift.com/container-platform/latest/authentication/using-service-accounts-as-oauth-client.html)
scenario. This gives you the possibility of defining clients associated
with service accounts. You just need to create the service account with
the proper annotations:

```bash
oc create -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
   name: <name>
   annotations:
      serviceaccounts.openshift.io/oauth-redirecturi.1: '<OUAUTH_CALLBACK_URL>'
EOF
```

In this scenario your `OAUTH_CLIENT_ID` will be
`system:serviceaccount:<serviceaccount_namespace>:<serviceaccount_name>`,
the OAUTH_CLIENT_SECRET is the API token of the service account
(`oc sa get-token <serviceaccount_name>`) and the OAUTH_CALLBACK_URL
is the value of the annotation
`serviceaccounts.openshift.io/oauth-redirecturi.1`. More details can
be found in the upstream documentation.

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "openshift"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional configuration

OpenShiftOAuthenticator expands OAuthenticator with the following config that may
be relevant to read more about in the configuration reference:

- {attr}`.OpenShiftOAuthenticator.allowed_groups`
- {attr}`.OpenShiftOAuthenticator.admin_groups`
