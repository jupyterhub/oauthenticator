(topic:google:extra-config)=

# Google specific configs

This guide covers optional, advanced configurations for Google OAuthenticator.

## Access via Google Groups

You can use Google Groups to manage user access and admin authorization for JupyterHub. To do this you must use a Service Account with domain-wide delegation to read group and user information.

The instructions below are to be performed after [finishing setting up Google](tutorials:provider-specific-setup:providers:google).

```{note}
The Google Cloud and Workspace UIs change frequently. For the most up-to-date instructions:
- [Creating a Service Account](https://docs.cloud.google.com/iam/docs/service-accounts-create)
- [Delegating domain-wide authority](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority)
- [Enabling a Google Cloud API](https://support.google.com/googleapi/answer/6158841?hl=en)
- [Creating a custom admin role](https://knowledge.workspace.google.com/admin/users/create-edit-and-delete-custom-admin-roles)
```

### Install the `googlegroups` `extra_requires`

Install the following in your hub environment:

```shell
pip install oauthenticator[googlegroups]
```

### Creating a Service Account and Credentials

1. Open the [**Service accounts** page](https://console.developers.google.com/iam-admin/serviceaccounts). If prompted, select a project.

1. Click add (`+`) **Create Service Account** and enter a name and description for the Service Account. The **Permissions (optional)** and **Principals with access (optional)** sections that follow are not required. When done select **Done**.

1. Once created, select your Service Account and go to **Keys**. Select **Add key** and **Create new key**. Select the **JSON** format for your key and select **Create**. See [Best practices for managing Service Account keys](https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys) for storing and using this key securely.

1. Return to your Service Account and copy the **OAuth 2 Client ID** (sometimes called **Unique ID** or just **Client ID**). You will need this for configuring domain-wide delegation.

### Delegating Domain-Wide Authority

```{note}
This step may require a Google Workspace administrator.
```

1. Go to your Google Workspace domain’s [Admin console](https://admin.google.com/).

1. Select **Security** -> **Access and data control** -> **API controls**.

1. Select **MANAGE DOMAIN WIDE DELEGATION**.

1. Select **Add new**.

1. In the **Client ID** field, enter the Client ID obtained from the Service Account creation steps above.

1. In the **OAuth scopes** field enter the scopes:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`

1. Select **Authorize**.

### Enable the Admin SDK API

1. Go to the [Google Cloud console API Library](https://console.cloud.google.com/apis/library?project=_).

1. Select your project from the project list.

1. Search for the **Admin SDK API**. This is a **Google Enterprise API** with the service name `admin.googleapis.com`.

1. Select **Enable**.

### Configure a Google Admin Account to Impersonate

```{note}
This step may require a Google Workspace administrator.
```

The Service Account you created will retrieve Google Group membership by impersonating an admin account with those privileges.

1. Go to your Google Workspace domain’s [Admin console](https://admin.google.com/).

1. Go to **Directory** -> **Users**.

1. Create the new user.

1. Select the user and then **Admin roles and privileges**.

1. Create a custom role that includes the **Groups.Read** and **Users.Read** **Admin API privileges** permissions.

1. Assign the role to the account.

### Configuring `jupyterhub_config.py`

Add the relevant lines below to your `jupyterhub_config.py`.

```python
# Email of the Google Workspace admin user that the Service Account will impersonate.
# This user must have read-only access to users and groups
c.GoogleOAuthenticator.gsuite_administrator = {'example.com': 'admin-for-jupyter@example.com'}

# Path to the JSON key file for your Service Account
c.GoogleOAuthenticator.google_service_account_keys = {'example.com': '/etc/jupyterhub/service_account.json'}

# List of Google Groups whose members should get admin rights on JupyterHub
c.GoogleOAuthenticator.admin_google_groups = {'example.com': ['jupyterhub-admins']}

# List of Google Groups whose members are allowed to log in to JupyterHub
c.GoogleOAuthenticator.allowed_google_groups = {'example.com': ['jupyterhub-users']}
```

## Retrieving `access_token` and `refresh_token`

In your `jupyterhub_config.py` do the following:

```python
c.OAuthenticator.extra_authorize_params = {'access_type': 'offline', 'approval_prompt': 'force'}
```

For more parameters see the [Google OAuth 2.0 documentation](https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient).
