"""test azure ad"""
import os
import re
import time
import uuid

from functools import partial

from unittest import mock

from pytest import fixture

import jwt
import pytest

from ..azuread import AzureAdOAuthenticator
from .mocks import setup_oauth_mock


def test_tenant_id_from_env():
    tenant_id = "some_random_id"
    with mock.patch.dict(os.environ, {"AAD_TENANT_ID": tenant_id}):
        aad = AzureAdOAuthenticator()
        assert aad.tenant_id == tenant_id


def user_model(tenant_id, client_id, name, **kwargs):
    """Return a user model"""
    # model derived from https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#v20
    now = int(time.time())

    user = {
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
    user.update(kwargs)

    id_token = jwt.encode(
        user,
        os.urandom(5),
    ).decode("ascii")

    return {
        "access_token": "abc123",
        "id_token": id_token,
    }


def _get_authenticator(**kwargs):
    return AzureAdOAuthenticator(
        tenant_id=str(uuid.uuid1()),
        client_id=str(uuid.uuid1()),
        client_secret=str(uuid.uuid1()),
        **kwargs
    )


@pytest.fixture
def azure_client(client):
    setup_oauth_mock(
        client,
        host=['login.microsoftonline.com'],
        access_token_path=re.compile('^/[^/]+/oauth2/token$'),
        token_request_style='jwt',
    )
    return client


@fixture
def get_authenticator(azure_client, **kwargs):
    return partial(_get_authenticator, http_client=azure_client)


@pytest.mark.parametrize(
    'username_claim',
    [
        None,
        'name',
        'oid',
        'preferred_username',
    ],
)
async def test_azuread(get_authenticator, username_claim, azure_client):
    authenticator = get_authenticator()
    if username_claim:
        authenticator.username_claim = username_claim

    handler = azure_client.handler_for_user(
        user_model(
            tenant_id=authenticator.tenant_id,
            client_id=authenticator.client_id,
            name="somebody"
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
    'allowed_groups,admin_groups,azuread_groups,expected',
    [
        ([], ['jupyterhub-admin'], ['jupyterhub-admin'], lambda r: bool(r) and r['admin']),
        ([], ['jupyterhub-admin'], ['jupyter-admin'], lambda r: not bool(r)),
        (['jupyterhub'], [], ['jupyterhub'], lambda r: bool(r) and not r['admin']),
        (['jupyterhub'], [], ['jupyter'], lambda r: not bool(r)),
        ([], [], ['jupyterhub'], lambda r: bool(r)),
        (['jupyterhub'], ['jupyterhub-admin'], ['jupyterhub', 'jupyterhub-admin'], lambda r: bool(r) and r['admin']),
        (['jupyterhub'], [], [], lambda r: not bool(r)),
        ([], [], [], lambda r: bool(r) and r.get('admin') is None)
    ],
)
async def test_azuread_groups(get_authenticator, azure_client, allowed_groups, admin_groups, azuread_groups, expected):
    authenticator = get_authenticator(
        scope=['openid', 'profile'],
        allowed_groups=allowed_groups,
        admin_groups=admin_groups,
    )

    handler = azure_client.handler_for_user(
        user_model(
            tenant_id=authenticator.tenant_id,
            client_id=authenticator.client_id,
            name="somebody",
            groups=azuread_groups,
        )
    )

    r = await authenticator.authenticate(handler)
    assert expected(r)
