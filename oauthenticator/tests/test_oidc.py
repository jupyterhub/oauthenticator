import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pytest import fixture, mark, param
from tornado import web
from traitlets.config import Config

from ..oidc import OIDCOAuthenticator
from .mocks import setup_oauth_mock

openid_provider_host = "oidc.example.com"
openid_provider_url = f"https://{openid_provider_host}"
client_id = "oidc-tests"


@fixture
def oidc_client(client):
    setup_oauth_mock(
        client,
        host=openid_provider_host,
        access_token_path='/oauth/token',
        user_path='/userinfo',
        client_id=client_id,
    )
    return client


def user_model():
    """Return a user model"""
    return {
        "email": "user1@example.com",
        "sub": "user1",
        "groups": ["group1"],
    }


@mark.parametrize(
    "class_config,expect_allowed,expect_admin",
    [
        # no allow config tested
        param({}, False, None, id="not_allowed"),
        # allow config, individually tested
        param({"allow_all": True}, True, None, id="allow_all"),
        param({"allowed_users": {"user1"}}, True, None, id="allowed_user"),
        param({"allowed_users": {"not-test-user"}}, False, None, id="not_allowed_user"),
        param({"admin_users": {"user1"}}, True, True, id="admin_users"),
        param({"admin_users": {"not-test-user"}}, False, None, id="not_admin_users"),
        # allow config, some combinations of two tested
        param(
            {
                "allow_all": False,
                "allowed_users": {"not-test-user"},
            },
            False,
            None,
            id="not_allow_all,not_allowed_user",
        ),
        param(
            # "11",
            {
                "admin_users": {"user1"},
                "allowed_users": {"not-test-user"},
            },
            True,
            True,
            id="admin_user_not_allowed_users",
        ),
        # common tests with allowed_groups and manage_groups
        param(
            # "20",
            {
                "allowed_groups": {"group1"},
                "auth_state_groups_key": "oauth_user.groups",
                "manage_groups": True,
            },
            True,
            None,
            id="allowed_groups",
        ),
        param(
            # "21",
            {
                "allowed_groups": {"test-user-not-in-group"},
                "auth_state_groups_key": "oauth_user.groups",
                "manage_groups": True,
            },
            False,
            None,
            id="not_allowed_groups",
        ),
        param(
            {
                "admin_groups": {"group1"},
                "auth_state_groups_key": "oauth_user.groups",
                "manage_groups": True,
            },
            True,
            True,
            id="admin_groups",
        ),
        param(
            {
                "admin_groups": {"test-user-not-in-group"},
                "auth_state_groups_key": "oauth_user.groups",
                "manage_groups": True,
            },
            False,
            False,
            id="not_admin_groups",
        ),
    ],
)
async def test_oidc(
    oidc_client,
    class_config,
    expect_allowed,
    expect_admin,
):
    c = Config()
    c.OIDCOAuthenticator = Config(class_config)
    c.OIDCOAuthenticator.openid_provider_url = openid_provider_url
    handled_user_model = user_model()
    handler = oidc_client.handler_for_user(handled_user_model)

    authenticator = OIDCOAuthenticator(config=c)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        if authenticator.manage_groups:
            assert set(auth_model) == {"name", "admin", "auth_state", "groups"}
        else:
            assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "access_token" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info == handled_user_model
        assert auth_model["name"] == user_info[authenticator.username_claim]
    else:
        assert auth_model is None


@mark.parametrize(
    "id_token_fields, expect_success",
    [
        param(
            {"aud": "wrong"},
            "error",
            id="wrong audience",
        ),
        param(
            {"iss": "wrong"},
            "error",
            id="wrong issuer",
        ),
        param(
            {"kid": "wrong"},
            "error",
            id="wrong key",
        ),
        param(
            {"sub": "user1"},
            True,
            id="ok",
        ),
    ],
)
async def test_oidc_id_token(
    oidc_client,
    id_token_fields,
    expect_success,
):
    c = Config()
    c.OIDCOAuthenticator.allowed_users = {"user1"}
    c.OIDCOAuthenticator.userdata_from_id_token = True
    c.OIDCOAuthenticator.openid_provider_url = openid_provider_url
    c.OIDCOAuthenticator.username_claim = "sub"
    c.OIDCOAuthenticator.client_id = client_id
    handled_user_model = user_model()
    id_token_content = {
        "aud": client_id,
        "iss": openid_provider_url,
    }
    id_token_content.update(handled_user_model)
    private_jwk = oidc_client.private_jwk
    kid = oidc_client.jwks["keys"][0]["kid"]
    if id_token_fields:
        id_token_content.update(id_token_fields)
        if "kid" in id_token_content:
            # use a mismatched key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            private_jwk = jwt.PyJWK(RSAAlgorithm.to_jwk(private_key, as_dict=True))

    handled_user_model["id_token"] = jwt.encode(
        id_token_content, key=private_jwk, algorithm="RS256", headers={"kid": kid}
    )
    handler = oidc_client.handler_for_user(handled_user_model)

    authenticator = OIDCOAuthenticator(config=c)

    def fetch_data():
        return oidc_client.jwks

    await authenticator._load_openid_configuration()
    authenticator.jwks_client.fetch_data = fetch_data
    if expect_success is True:
        auth_model = await authenticator.get_authenticated_user(handler, None)
        assert auth_model
        assert "oauth_user" in auth_model["auth_state"]
        assert auth_model["auth_state"]["oauth_user"] == id_token_content
    elif expect_success == 'error':
        with pytest.raises(web.HTTPError):
            auth_model = await authenticator.get_authenticated_user(handler, None)
    elif expect_success is False:
        auth_model = await authenticator.get_authenticated_user(handler, None)
        assert auth_model is None
    else:
        raise ValueError(f"{expect_success=}")
