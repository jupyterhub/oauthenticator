(topic:google:extra-config)=

# Google specific configs

The instructions below are to be performed after [finishing setting up Google](tutorials:provider-specific-setup:providers:google).

If you'd like to rely on Google Groups for managing access to JupyterHub, you'll need additional setup. Google does not offer an API for users to check their own group memberships. Because of this, you must use a Service Account with domain-wide delegation to read group and user information.

To enable this, you must:

1. Install the `googlegroups` `extra_requires` in your hub environment:

  ```shell
  pip install oauthenticator[googlegroups]
  ```

1. Create a Google Cloud Service Account that has read-only access to groups and users and can impersonate a Google Workspace admin user.

1. Enable the Admin SDK API.


## Instructions
The Google Cloud and Workspace UIs change frequently. For the most up-to-date instructions:

* [Creating a Service Account](https://cloud.google.com/iam/docs/service-accounts-create)
* [Delegating domain-wide authority](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority)

### Creating a Service Account and Credentials

1. Open the [**Service accounts** page](https://console.developers.google.com/iam-admin/serviceaccounts). If prompted, select a project.
1. Click add (`+`) **Create Service Account** and enter a name and description for the Service Account. You can use the default Service Account ID, or choose a different, unique one. The **Permissions (optional)** and **Principals with access (optional)** sections that follow are not required. When done select **Done**.
1. Once created, select your Service Account and go to **Keys**. Select **Add key** and **Create new key**.
1. In the window that appears, select the **JSON** format for your key and select **Create**.
1. Your new public/private key pair is generated and the private key downloaded to your machine; it serves as the only copy of this key. For information on how to store it securely, as well as other best practices, see [Best practices for managing Service Account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys).
1. Click **Close** on the **Private key saved to your computer** dialog, then click **Done** to return to the table of your Service Accounts.
1. Locate the newly-created Service Account in the table and copy the **OAuth 2 Client ID** (sometimes called **Unique ID** or **Client ID**). You will need this for configuring domain-wide delegation.
1. If you haven't yet configured your app's OAuth consent screen, you must do so before you can enable domain-wide delegation. Follow the on-screen instructions to configure the OAuth consent screen.

### Delegating Domain-Wide Authority

```{note}
This step may require a Google Workspace administrator.
```

1. Go to your Google Workspace domain’s [Admin console](https://admin.google.com/).
1. Select **Security** -> **Access and data control** -> **API controls**.
1. Select **MANAGE DOMAIN WIDE DELEGATION**.
1. Select **Add new**.
1. In the **Client ID** field, enter the client ID obtained from the Service Account creation steps above.
1. In the **OAuth scopes** field enter the scopes `https://www.googleapis.com/auth/admin.directory.user.readonly, https://www.googleapis.com/auth/admin.directory.group.readonly`.
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

Add the relevant lines below to your `jupyterhub_config.py`:

**Note:** If you remove a member from a Google Group, you will have to force this user to log in again for the change to take effect.

#### Managing Admins and Allowed Users

```python
c.GoogleOAuthenticator.gsuite_administrator = {'example.com': 'someuser'}
c.GoogleOAuthenticator.google_service_account_keys = {'example.com': '/path/to/service_account.json'}
c.GoogleOAuthenticator.admin_google_groups = {'example.com': ['someadmingroup']}
c.GoogleOAuthenticator.allowed_google_groups = {'example.com': ['somegroupwithaccess', 'othergroupwithaccess'] }
```

#### Allowing Users via Groups

```python
c.GoogleOAuthenticator.gsuite_administrator = {'example.com': 'someuser'}
c.GoogleOAuthenticator.google_service_account_keys = {'example.com': '/path/to/service_account.json'}
c.GoogleOAuthenticator.allowed_google_groups = {'example.com': ['somegroupwithaccess', 'othergroupwithaccess'] }
```

#### Managing Admins via Groups

```python
c.GoogleOAuthenticator.gsuite_administrator = {'example.com': 'someuser'}
c.GoogleOAuthenticator.google_service_account_keys = {'example.com': '/path/to/service_account.json'}
c.GoogleOAuthenticator.admin_google_groups = {'example.com': ['someadmingroup']}
```


## Retrieving `access_token` and `refresh_token`

In your `jupyterhub_config.py` do the following:

```python
c.OAuthenticator.extra_authorize_params = {'access_type': 'offline', 'approval_prompt': 'force'}
```

For more parameters see the [Google OAuth 2.0 documentation](https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient).
