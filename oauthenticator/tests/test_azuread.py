"""test azure ad"""

import json
import logging
import os
import re
import time
import uuid
from unittest import mock

import jwt
import pytest
from pytest import fixture, mark, raises
from traitlets.config import Config

from ..azuread import AzureAdOAuthenticator
from .mocks import setup_oauth_mock


@fixture
def azure_client(client):
    setup_oauth_mock(
        client,
        host=['login.microsoftonline.com'],
        access_token_path=re.compile('^/[^/]+/oauth2/token$'),
    )
    return client


def user_model(tenant_id, client_id, name):
    """Return a user model"""
    # id_token derived from https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#v20
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
                "group1",
            ],
            # different from 'groups' for tests
            "grp": [
                "96000b2c-7333-4f6e-a2c3",
                "a992b3d5-1966-4af4-abed",
                "ceb90a42-030f-44f1-a0c7",
            ],
        },
        os.urandom(5),
    )

    return {
        "access_token": "abc123",
        "id_token": id_token,
    }


@mark.parametrize(
    "test_variation_id,class_config,expect_allowed,expect_admin",
    [
        # no allow config tested
        ("00", {}, False, None),
        # allow config, individually tested
        ("01", {"allow_all": True}, True, None),
        ("02", {"allowed_users": {"user1"}}, True, None),
        ("03", {"allowed_users": {"not-test-user"}}, False, None),
        ("04", {"admin_users": {"user1"}}, True, True),
        ("05", {"admin_users": {"not-test-user"}}, False, None),
        # allow config, some combinations of two tested
        (
            "10",
            {
                "allow_all": False,
                "allowed_users": {"not-test-user"},
            },
            False,
            None,
        ),
        (
            "11",
            {
                "admin_users": {"user1"},
                "allowed_users": {"not-test-user"},
            },
            True,
            True,
        ),
        # test username_claim
        (
            "20",
            {"allow_all": True, "username_claim": "name"},
            True,
            None,
        ),
        (
            "21",
            {"allow_all": True, "username_claim": "oid"},
            True,
            None,
        ),
        (
            "22",
            {"allow_all": True, "username_claim": "preferred_username"},
            True,
            None,
        ),
        # test user_groups_claim (deprecated)
        (
            "30",
            {
                "allow_all": True,
                "user_groups_claim": "groups",
                "manage_groups": True,
            },
            True,
            None,
        ),
        (
            "31",
            {
                "allow_all": True,
                "manage_groups": True,
                "user_groups_claim": "grp",
            },
            True,
            None,
        ),
        # common tests with allowed_groups and manage_groups
        (
            "40",
            {
                "allowed_groups": {"group1"},
                "manage_groups": True,
            },
            True,
            None,
        ),
        (
            "41",
            {
                "allowed_groups": {"test-user-not-in-group"},
                "manage_groups": True,
            },
            False,
            None,
        ),
        (
            "42",
            {
                "admin_groups": {"group1"},
                "manage_groups": True,
            },
            True,
            True,
        ),
        (
            "43",
            {
                "admin_groups": {"test-user-not-in-group"},
                "manage_groups": True,
            },
            False,
            False,
        ),
    ],
)
async def test_azuread(
    azure_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.AzureAdOAuthenticator = Config(class_config)
    c.AzureAdOAuthenticator.tenant_id = str(uuid.uuid1())
    c.AzureAdOAuthenticator.client_id = str(uuid.uuid1())
    c.AzureAdOAuthenticator.client_secret = str(uuid.uuid1())
    authenticator = AzureAdOAuthenticator(config=c)
    manage_groups = False
    if "manage_groups" in class_config:
        if hasattr(authenticator, "manage_groups"):
            manage_groups = authenticator.manage_groups
        else:
            pytest.skip("manage_groups requires jupyterhub 2.2")

    handled_user_model = user_model(
        tenant_id=authenticator.tenant_id,
        client_id=authenticator.client_id,
        name="user1",
    )
    handler = azure_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        expected_keys = {"name", "admin", "auth_state"}
        if manage_groups:
            expected_keys.add("groups")
        assert set(auth_model) == expected_keys
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "access_token" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info["aud"] == authenticator.client_id
        assert auth_model["name"] == user_info[authenticator.username_claim]
        if manage_groups:
            groups = auth_model['groups']
            assert (
                groups == user_info[authenticator.auth_state_groups_key.rsplit(".")[-1]]
            )
    else:
        assert auth_model is None


async def test_tenant_id_from_env():
    tenant_id = "some_random_id"
    with mock.patch.dict(os.environ, {"AAD_TENANT_ID": tenant_id}):
        aad = AzureAdOAuthenticator()
        assert aad.tenant_id == tenant_id


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "user_groups_claim",
            {"user_groups_claim": "groups", "manage_groups": True},
            {"auth_state_groups_key": "user.groups"},
            logging.WARNING,
            "AzureAdOAuthenticator.user_groups_claim is deprecated in OAuthenticator 17. Use AzureAdOAuthenticator.auth_state_groups_key = 'user.groups'",
        ),
    ],
)
async def test_deprecated_config(
    caplog,
    test_variation_id,
    class_config,
    expect_config,
    expect_loglevel,
    expect_message,
):
    """
    Tests that a warning is emitted when using a deprecated config and that
    configuring the old config ends up configuring the new config.
    """
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.AzureAdOAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            AzureAdOAuthenticator(config=c, log=test_logger)
    else:
        authenticator = AzureAdOAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples
