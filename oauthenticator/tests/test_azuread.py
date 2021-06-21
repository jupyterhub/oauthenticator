"""test azure ad"""
import os
import re
import time
import uuid
from unittest import mock

import jwt
import pytest

from ..azuread import AzureAdOAuthenticator
from .mocks import setup_oauth_mock


def test_tenant_id_from_env():
    tenant_id = "some_random_id"
    with mock.patch.dict(os.environ, {"AAD_TENANT_ID": tenant_id}):
        aad = AzureAdOAuthenticator()
        assert aad.tenant_id == tenant_id


def user_model(tenant_id, client_id, name):
    """Return a user model"""
    # model derived from https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#v20
    now = int(time.time())
    id_token = jwt.encode(
        {
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
        },
        os.urandom(5),
    ).decode("ascii")

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
