"""test azure ad"""
import os
import re
import time
import uuid
from unittest import mock

import jwt
import pytest

from ..azuread import AzureAdOAuthenticator
from ..azuread import PYJWT_2
from .mocks import setup_oauth_mock


def test_tenant_id_from_env():
    tenant_id = "some_random_id"
    with mock.patch.dict(os.environ, {"AAD_TENANT_ID": tenant_id}):
        aad = AzureAdOAuthenticator()
        assert aad.tenant_id == tenant_id


def user_model(tenant_id, client_id, name, roles=None):
    """Return a user model"""
    # model derived from https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#v20
    now = int(time.time())
    token_body = {
        "ver": "2.0",
        "iss": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "sub": "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "name": name,
        "preferred_username": name,
        "oid": str(uuid.uuid1()),
        "tid": tenant_id,
        "nonce": "123523",
        "aio": "Df2UVXL1ix!lMCWMSOJBcFatzcGfvFGhjKv8q5g0x732dR5MB5BisvGQO7YWByjd8iQDLq!eGbIDakyp5mnOrcdqHeYSnltepQmRp6AIZ8jY",
    }
    if roles:
        token_body["roles"] = roles
    id_token = jwt.encode(token_body, os.urandom(5))
    if not PYJWT_2:
        id_token = id_token.decode("ascii")

    return {
        "access_token": "abc123",
        "id_token": id_token,
    }


@pytest.fixture
def azure_client(client):
    setup_oauth_mock(
        client,
        host=['login.microsoftonline.com'],
        access_token_path=re.compile('^/[^/]+/oauth2/token$'),
        token_request_style='jwt',
    )
    return client


@pytest.mark.parametrize(
    'username_claim',
    [
        None,
        'name',
        'oid',
        'preferred_username',
    ],
)
async def test_azuread(username_claim, azure_client):
    authenticator = AzureAdOAuthenticator(
        tenant_id=str(uuid.uuid1()),
        client_id=str(uuid.uuid1()),
        client_secret=str(uuid.uuid1()),
    )
    if username_claim:
        authenticator.username_claim = username_claim

    handler = azure_client.handler_for_user(
        user_model(
            tenant_id=authenticator.tenant_id,
            client_id=authenticator.client_id,
            name="somebody",
        )
    )

    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'user' in auth_state
    jwt_user = auth_state['user']
    assert jwt_user['aud'] == authenticator.client_id

    name = user_info['name']
    assert name == jwt_user[authenticator.username_claim]


@pytest.mark.parametrize(
    'is_admin',
    [
        True,
        False,
    ],
)
async def test_azuread_admin(is_admin, azure_client):
    authenticator = AzureAdOAuthenticator(
        tenant_id=str(uuid.uuid1()),
        client_id=str(uuid.uuid1()),
        client_secret=str(uuid.uuid1()),
        admin_role_ids=[str(uuid.uuid1())],
    )

    roles = []

    if is_admin:
        roles.extend(authenticator.admin_role_ids)

    handler = azure_client.handler_for_user(
        user_model(
            tenant_id=authenticator.tenant_id,
            client_id=authenticator.client_id,
            name="somebody",
            roles=(roles, None)[roles == []],
        )
    )

    user_info = await authenticator.authenticate(handler)
    auth_state = user_info['auth_state']
    has_admin_role = False if 'admin' not in user_info.keys() else user_info["admin"]

    assert (
        sorted(user_info) == ['admin', 'auth_state', 'name']
        if is_admin
        else sorted(user_info) == ['auth_state', 'name']
    )
    assert is_admin == has_admin_role
    assert is_admin if has_admin_role else not is_admin
    assert not is_admin if not has_admin_role else is_admin


@pytest.mark.parametrize(
    'is_allowed',
    [
        True,
        False,
    ],
)
@pytest.mark.parametrize(
    'is_admin',
    [
        True,
        False,
    ],
)
@pytest.mark.parametrize(
    'allowed_role_ids',
    [
        [],
        ["somevalue"],
        ["somevalue", "someothervalue"],
    ],
)
@pytest.mark.parametrize(
    'admin_role_ids',
    [
        [],
        ["somevalue"],
        ["somevalue", "someothervalue"],
    ],
)
async def test_azuread_allowed(
    is_allowed, is_admin, allowed_role_ids, admin_role_ids, azure_client
):
    authenticator = AzureAdOAuthenticator(
        tenant_id=str(uuid.uuid1()),
        client_id=str(uuid.uuid1()),
        client_secret=str(uuid.uuid1()),
        allowed_user_role_ids=allowed_role_ids,
        admin_role_ids=admin_role_ids,
    )

    roles = []

    if is_allowed and allowed_role_ids != []:
        roles.append(authenticator.allowed_user_role_ids)

    if is_admin and admin_role_ids != []:
        roles.append(authenticator.admin_role_ids)

    handler = azure_client.handler_for_user(
        user_model(
            tenant_id=authenticator.tenant_id,
            client_id=authenticator.client_id,
            name="somebody",
            roles=(roles, None)[roles == []],
        )
    )

    user_info = await authenticator.authenticate(handler)
    authenticated = user_info != None
    auth_state = [] if not authenticated else user_info["auth_state"]
    user = [] if not authenticated else auth_state["user"]
    user_roles = (
        [] if not authenticated or 'roles' not in user.keys() else user["roles"]
    )

    has_allowed_role = [r for r in allowed_role_ids if r in user_roles] != []
    has_admin_role = [r for r in admin_role_ids if r in user_roles] != []
    allow_required = authenticator.allowed_user_role_ids != []
    allowed_as_admin = (allow_required and has_admin_role) or not allow_required
    allowed_as_user = (allow_required and has_allowed_role) or not allow_required

    if allowed_as_admin or allowed_as_user:
        assert authenticated
    elif not allowed_as_admin and not allowed_as_user:
        assert not authenticated
