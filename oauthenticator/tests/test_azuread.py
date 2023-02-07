"""test azure ad"""
import os
import re
import time
import uuid
from unittest import mock

import jwt
import pytest
from traitlets.config import Config

from ..azuread import AzureAdOAuthenticator
from .mocks import setup_oauth_mock


async def test_tenant_id_from_env():
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
            "preferred_username": "preferred",
            "oid": str(uuid.uuid1()),
            "tid": tenant_id,
            "nonce": "123523",
            "aio": "Df2UVXL1ix!lMCWMSOJBcFatzcGfvFGhjKv8q5g0x732dR5MB5BisvGQO7YWByjd8iQDLq!eGbIDakyp5mnOrcdqHeYSnltepQmRp6AIZ8jY",
            "groups": [
                "96000b2c-7333-4f6e-a2c3-e7608fa2d131",
                "a992b3d5-1966-4af4-abed-6ef021417be4",
                "ceb90a42-030f-44f1-a0c7-825b572a3b07",
            ],
            "grp": [
                "96000b2c-7333-4f6e-a2c3-e7608fa2d131",
                "a992b3d5-1966-4af4-abed-6ef021417be4",
                "ceb90a42-030f-44f1-a0c7-825b572a3b07",
            ],
        },
        os.urandom(5),
    )

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
    'username_claim, user_groups_claim, manage_groups',
    [
        (None, None, False),
        ('name', None, False),
        ('oid', None, False),
        ('preferred_username', None, False),
        (None, None, True),
        (None, "groups", True),
        (None, "grp", True),
    ],
)
async def test_azuread(username_claim, user_groups_claim, manage_groups, azure_client):
    cfg = Config()
    cfg.AzureAdOAuthenticator = Config(
        {
            "tenant_id": str(uuid.uuid1()),
            "client_id": str(uuid.uuid1()),
            "client_secret": str(uuid.uuid1()),
            "manage_groups": manage_groups,
        }
    )

    if username_claim:
        cfg.AzureAdOAuthenticator.username_claim = username_claim
    if user_groups_claim:
        cfg.AzureAdOAuthenticator.user_groups_claim = user_groups_claim

    authenticator = AzureAdOAuthenticator(config=cfg)

    handler = azure_client.handler_for_user(
        user_model(
            tenant_id=authenticator.tenant_id,
            client_id=authenticator.client_id,
            name="somebody",
        )
    )

    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'groups', 'name']
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'user' in auth_state

    auth_state_user_info = auth_state['user']
    assert auth_state_user_info['aud'] == authenticator.client_id

    username = user_info['name']
    if username_claim:
        assert username == auth_state_user_info[username_claim]
    else:
        # The default AzureADOAuthenticator `username_claim` is "name"
        assert username == auth_state_user_info["name"]

    if user_groups_claim:
        groups = user_info['groups']
        assert groups == auth_state_user_info[user_groups_claim]
