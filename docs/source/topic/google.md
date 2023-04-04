(topic:google:extra-config)=

# Google specific configs

**Note:** The instructions below are to be performed after [finishing setting up google](tutorials:provider-specific-setup:providers:google)

If you'd like to rely on google groups for managing access to jupyterhub you'd have to do the following:

## Install googlegroups `extra_requires`

```shell
pip install oauthenticator[googlegroups]
```

## Create a service account that only has read access to groups and users that can impersonate a G Suite admin user

Google does not offer a way for letting users check which groups they belong to via an API,
because of this caveat the way to be able to check what groups an user belongs to we have use a service account
and give it read only access to users and groups.

## Instructions

### Create service account and credentials

1. Open the [**Service accounts** page](https://console.developers.google.com/iam-admin/serviceaccounts). If prompted, select a project.
2. Click add (`+`) **Create Service Account**, enter a name and description for the service account. You can use the default service account ID, or choose a different, unique one. When done click **Create**.
3. The **Service account permissions (optional)** section that follows is not required. Click **Continue**.
4. On the **Grant users access to this service account** screen, scroll down to the **Create key** section. Click add (`+`) **Create key**.
5. n the side panel that appears, select the format for your key: **JSON**
6. Click **Create**. Your new public/private key pair is generated and downloaded to your machine; it serves as the only copy of this key. For information on how to store it securely, as well as other best practices, see [Best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys).
7. Click **Close** on the **Private key saved to your computer** dialog, then click **Done** to return to the table of your service accounts.
8. Locate the newly-created service account in the table. Under `Actions`, click then **Edit**.
9. In the service account details, click 🔽 **Show domain-wide delegation**, then ensure the **Enable G Suite Domain-wide Delegation** checkbox is checked.
10. If you haven't yet configured your app's OAuth consent screen, you must do so before you can enable domain-wide delegation. Follow the on-screen instructions to configure the OAuth consent screen, then repeat the above steps and re-check the checkbox.
11. Click **Save** to update the service account, and return to the table of service accounts. A new column, **Domain-wide delegation**, can be seen. Click **View Client ID**, to obtain and make a note of the client ID.

### Delegate domain-wide authority to your service account

1. Go to your G Suite domain’s [Admin console](https://admin.google.com/).
2. Select **Security** from the list of controls. If you don't see **Security** listed, select **More controls** from the gray bar at the bottom of the page, then select **Security** from the list of controls.
3. Select **Advanced settings** from the list of options.
4. Select **Manage API client access** in the **Authentication** section.
5. In the **Client name** field, enter the client ID obtained from the service account creation steps above.
6. In the **One or More API Scopes** field enter the scopes required for your application (for a list of possible scopes, see [Authorize requests](https://developers.google.com/admin-sdk/directory/v1/guides/authorizing)). Please enter: `https://www.googleapis.com/auth/admin.directory.user.readonly, https://www.googleapis.com/auth/admin.directory.group.readonly`
7. Click the **Authorize** button.

### Configure `jupyterhub_config.py` add the lines below:

**Note:** if you remove a member from a google group you will have to force this user to login again in order for the change to take effect

#### if you want to manage admin users and allowed users via google groups

```python
c.GoogleOAuthenticator.gsuite_administrator = {'example.com': 'someuser'}
c.GoogleOAuthenticator.google_service_account_keys = {'example.com': '/path/to/service_account.json'}
c.GoogleOAuthenticator.admin_google_groups = {'example.com': ['someadmingroup']}
c.GoogleOAuthenticator.allowed_google_groups = {'example.com': ['somegroupwithaccess', 'othergroupwithaccess'] }
```

#### if you only want to allow users via google groups

```python
c.GoogleOAuthenticator.gsuite_administrator = {'example.com': 'someuser'}
c.GoogleOAuthenticator.google_service_account_keys = {'example.com': '/path/to/service_account.json'}
c.GoogleOAuthenticator.allowed_google_groups = {'example.com': ['somegroupwithaccess', 'othergroupwithaccess'] }
```

#### if you want to manage admin users via google groups

```python
c.GoogleOAuthenticator.gsuite_administrator = {'example.com': 'someuser'}
c.GoogleOAuthenticator.google_service_account_keys = {'example.com': '/path/to/service_account.json'}
c.GoogleOAuthenticator.admin_google_groups = {'example.com': ['someadmingroup']}
```

### You are done!

## How to retrieve an `access_token` and `refresh_token` for all scopes at once

In your `jupyterhub_config.py` do the following:

```python
c.OAuthenticator.extra_authorize_params = {'access_type': 'offline', 'approval_prompt': 'force'}
```

For more params you can use go [here](https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient)
