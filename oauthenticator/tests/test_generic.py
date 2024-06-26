import json
import re
from functools import partial

import jwt
from pytest import fixture, mark, raises
from traitlets.config import Config

from ..generic import GenericOAuthenticator
from .mocks import setup_oauth_mock

client_id = "jupyterhub-oauth-client"


def user_model(username, **kwargs):
    """Return a user model"""
    return {
        "username": username,
        "aud": client_id,
        "sub": "oauth2|cilogon|http://cilogon.org/servera/users/43431",
        "scope": "basic",
        "groups": ["group1"],
        **kwargs,
    }


@fixture(params=["id_token", "userdata_url"])
def userdata_from_id_token(request):
    return request.param == "id_token"


@fixture
def generic_client(client):
    setup_oauth_mock(
        client,
        host='generic.horse',
        access_token_path='/oauth/access_token',
        user_path='/oauth/userinfo',
        scope='basic',
    )
    return client


@fixture
def generic_client_variant(client, userdata_from_id_token):
    setup_oauth_mock(
        client,
        host='generic.horse',
        access_token_path='/oauth/access_token',
        user_path='/oauth/userinfo',
    )
    return client


def _get_authenticator(**kwargs):
    return GenericOAuthenticator(
        token_url='https://generic.horse/oauth/access_token',
        userdata_url='https://generic.horse/oauth/userinfo',
        client_id=client_id,
        **kwargs,
    )


def _get_authenticator_for_id_token(**kwargs):
    return GenericOAuthenticator(
        token_url='https://generic.horse/oauth/access_token',
        userdata_from_id_token=True,
        client_id=client_id,
        **kwargs,
    )


@fixture
def get_authenticator(generic_client):
    """
    http_client can't be configured, only passed as argument to the constructor.
    """
    return partial(_get_authenticator, http_client=generic_client)


@fixture
def get_authenticator_variant(generic_client, userdata_from_id_token):
    """
    http_client can't be configured, only passed as argument to the constructor.
    """
    return partial(
        (
            _get_authenticator_for_id_token
            if userdata_from_id_token
            else _get_authenticator
        ),
        http_client=generic_client,
    )


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
        ("06", {"allowed_groups": {"group1"}, "manage_groups": True}, True, None),
        (
            "07",
            {"allowed_groups": {"test-user-not-in-group"}, "manage_groups": True},
            False,
            None,
        ),
        ("08", {"admin_groups": {"group1"}, "manage_groups": True}, True, True),
        (
            "09",
            {"admin_groups": {"test-user-not-in-group"}, "manage_groups": True},
            False,
            False,
        ),
        # allow config, some combinations of two tested
        (
            "10",
            {
                "allow_all": False,
                "allowed_users": {"not-test-user"},
                "manage_groups": True,
            },
            False,
            None,
        ),
        (
            "11",
            {
                "allowed_users": {"not-test-user"},
                "admin_users": {"user1"},
                "manage_groups": True,
            },
            True,
            True,
        ),
        (
            "12",
            {
                "allowed_groups": {"group1"},
                "admin_groups": {"group1"},
                "manage_groups": True,
            },
            True,
            True,
        ),
        (
            "13",
            {
                "allowed_groups": {"group1"},
                "admin_groups": {"test-user-not-in-group"},
                "manage_groups": True,
            },
            True,
            False,
        ),
        (
            "14",
            {
                "allowed_groups": {"test-user-not-in-group"},
                "admin_groups": {"group1"},
                "manage_groups": True,
            },
            True,
            True,
        ),
        (
            "15",
            {
                "allowed_groups": {"test-user-not-in-group"},
                "admin_groups": {"test-user-not-in-group"},
                "manage_groups": True,
            },
            False,
            False,
        ),
        (
            "16",
            {
                "admin_users": {"user1"},
                "admin_groups": {"group1"},
                "manage_groups": True,
            },
            True,
            True,
        ),
        (
            "17",
            {
                "admin_users": {"user1"},
                "admin_groups": {"test-user-not-in-group"},
                "manage_groups": True,
            },
            True,
            True,
        ),
        (
            "18",
            {
                "admin_users": {"not-test-user"},
                "admin_groups": {"group1"},
                "manage_groups": True,
            },
            True,
            True,
        ),
        (
            "19",
            {
                "admin_users": {"not-test-user"},
                "admin_groups": {"test-user-not-in-group"},
                "manage_groups": True,
            },
            False,
            False,
        ),
        (
            "20",
            {
                "manage_groups": True,
                "allow_all": True,
            },
            True,
            None,
        ),
    ],
)
async def test_generic(
    get_authenticator_variant,
    generic_client_variant,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
    userdata_from_id_token,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.GenericOAuthenticator = Config(class_config)
    c.GenericOAuthenticator.username_claim = "username"
    authenticator = get_authenticator_variant(config=c)
    manage_groups = False
    if "manage_groups" in class_config:
        manage_groups = authenticator.manage_groups

    handled_user_model = user_model("user1")
    if userdata_from_id_token:
        handled_user_model = dict(id_token=jwt.encode(handled_user_model, key="foo"))
    handler = generic_client_variant.handler_for_user(handled_user_model)
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
        assert "oauth_user" in auth_state
        assert "refresh_token" in auth_state
        assert "scope" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert auth_model["name"] == user_info[authenticator.username_claim]
        if manage_groups:
            assert auth_model["groups"] == user_info[authenticator.claim_groups_key]

    else:
        assert auth_model == None


async def test_username_claim_callable(
    get_authenticator,
    generic_client,
):
    c = Config()
    c.GenericOAuthenticator = Config()

    def username_claim(user_info):
        username = user_info["sub"]
        if username.startswith("oauth2|cilogon"):
            cilogon_sub = username.rsplit("|", 1)[-1]
            cilogon_sub_parts = cilogon_sub.split("/")
            username = f"oauth2|cilogon|{cilogon_sub_parts[3]}|{cilogon_sub_parts[5]}"
        return username

    c.GenericOAuthenticator.username_claim = username_claim
    c.GenericOAuthenticator.allow_all = True
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model("user1")
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    assert auth_model["name"] == "oauth2|cilogon|servera|43431"


async def test_generic_data(get_authenticator, generic_client):
    c = Config()
    c.GenericOAuthenticator.allow_all = True
    authenticator = get_authenticator()

    handled_user_model = user_model("user1")
    handler = generic_client.handler_for_user(handled_user_model)
    data = {"testing": "data"}
    auth_model = await authenticator.authenticate(handler, data)

    assert auth_model


@mark.parametrize(
    ["allowed_scopes", "allowed"], [(["advanced"], False), (["basic"], True)]
)
async def test_allowed_scopes(
    get_authenticator, generic_client, allowed_scopes, allowed
):
    c = Config()
    c.GenericOAuthenticator.allowed_scopes = allowed_scopes
    c.GenericOAuthenticator.scope = list(allowed_scopes)
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model("user1")
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.authenticate(handler)
    assert allowed == await authenticator.check_allowed(auth_model["name"], auth_model)


async def test_allowed_scopes_validation_scope_subset(get_authenticator):
    c = Config()
    # Test that if we require more scopes than we request, validation fails
    c.GenericOAuthenticator.allowed_scopes = ["a", "b"]
    c.GenericOAuthenticator.scope = ["a"]
    with raises(
        ValueError,
        match=re.escape(
            "Allowed scopes must be a subset of requested scopes. ['a'] is requested but ['a', 'b'] is allowed"
        ),
    ):
        get_authenticator(config=c)


async def test_generic_callable_username_key(get_authenticator, generic_client):
    c = Config()
    c.GenericOAuthenticator.allow_all = True
    c.GenericOAuthenticator.username_key = lambda r: r["alternate_username"]
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model("user1", alternate_username="zoe")
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    assert auth_model["name"] == "zoe"


async def test_generic_claim_groups_key_callable(get_authenticator, generic_client):
    c = Config()
    c.GenericOAuthenticator.claim_groups_key = lambda r: r["policies"]["roles"]
    c.GenericOAuthenticator.allowed_groups = ["super_user"]
    c.GenericOAuthenticator.manage_groups = True
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model("user1", policies={"roles": ["super_user"]})
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    assert auth_model


async def test_generic_claim_groups_key_nested_strings(
    get_authenticator, generic_client
):
    c = Config()
    c.GenericOAuthenticator.claim_groups_key = "permissions.groups"
    c.GenericOAuthenticator.admin_groups = ["super_user"]
    c.GenericOAuthenticator.manage_groups = True
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model("user1", permissions={"groups": ["super_user"]})
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    assert auth_model
    assert auth_model["admin"]


async def test_generic_auth_state_groups_key_callable(
    get_authenticator, generic_client
):
    c = Config()
    c.GenericOAuthenticator.auth_state_groups_key = lambda auth_state: auth_state[
        "oauth_user"
    ]["policies"]["roles"]
    c.GenericOAuthenticator.allowed_groups = ["super_user"]
    c.GenericOAuthenticator.manage_groups = True
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model("user1", policies={"roles": ["super_user"]})
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    assert auth_model


async def test_generic_auth_state_groups_key_nested_strings(
    get_authenticator, generic_client
):
    c = Config()
    c.GenericOAuthenticator.auth_state_groups_key = "oauth_user.permissions.groups"
    c.GenericOAuthenticator.admin_groups = ["super_user"]
    c.GenericOAuthenticator.manage_groups = True
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model("user1", permissions={"groups": ["super_user"]})
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    assert auth_model
    assert auth_model["admin"]


@mark.parametrize(
    ("trait_name", "value"),
    [
        ("auth_state_groups_key", "oauth_user.permissions.groups"),
        ("admin_groups", ["super_users"]),
        ("allowed_groups", ["all_users"]),
    ],
)
async def test_generic_manage_groups_required(get_authenticator, trait_name, value):
    c = Config()
    setattr(c.GenericOAuthenticator, trait_name, value)
    with raises(
        ValueError,
        match=re.escape(
            rf'GenericOAuthenticator.{trait_name} requires GenericOAuthenticator.manage_groups to also be set'
        ),
    ):
        get_authenticator(config=c)


@mark.parametrize(
    "name, allowed",
    [
        ("allowed", True),
        ("notallowed", False),
    ],
)
async def test_check_allowed_no_auth_state(get_authenticator, name, allowed):
    authenticator = get_authenticator(allowed_users={"allowed"})
    # allow check always gets called with no auth model during Hub startup
    # these are previously-allowed users who should pass until subsequent
    # this check is removed in JupyterHub 5
    assert await authenticator.check_allowed(name, None)
