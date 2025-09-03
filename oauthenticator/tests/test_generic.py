import json
import logging
import re
from functools import partial

import jwt
from pytest import fixture, mark, param, raises
from traitlets.config import Config

from ..generic import GenericOAuthenticator
from .mocks import setup_oauth_mock

client_id = "jupyterhub-oauth-client"


def user_model(username, **kwargs):
    """Return a user model"""
    model = {
        "username": username,
        "aud": client_id,
        "sub": "oauth2|cilogon|http://cilogon.org/servera/users/43431",
        "scope": "basic",
        "groups": ["group1"],
    }
    model.update(kwargs)
    return model


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
        # common tests with allowed_groups and manage_groups
        ("20", {"allowed_groups": {"group1"}, "manage_groups": True}, True, None),
        (
            "21",
            {"allowed_groups": {"test-user-not-in-group"}, "manage_groups": True},
            False,
            None,
        ),
        ("22", {"admin_groups": {"group1"}, "manage_groups": True}, True, True),
        (
            "23",
            {"admin_groups": {"test-user-not-in-group"}, "manage_groups": True},
            False,
            False,
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


def sync_auth_state_hook(authenticator, auth_state):
    auth_state["sync"] = True
    auth_state["hook_groups"] = ["alpha", "beta", auth_state["oauth_user"]["username"]]
    return auth_state


async def async_auth_state_hook(authenticator, auth_state):
    auth_state["async"] = True
    auth_state["hook_groups"] = [
        "alpha",
        "beta",
        auth_state[authenticator.user_auth_state_key]["username"],
    ]
    return auth_state


@mark.parametrize(
    "auth_state_hook",
    [param(sync_auth_state_hook, id="sync"), param(async_auth_state_hook, id="async")],
)
async def test_modify_auth_state_hook(
    get_authenticator, generic_client, auth_state_hook
):
    c = Config()
    c.GenericOAuthenticator.allow_all = True
    c.OAuthenticator.modify_auth_state_hook = auth_state_hook
    c.OAuthenticator.auth_state_groups_key = "hook_groups"
    c.OAuthenticator.manage_groups = True

    authenticator = get_authenticator(config=c)
    assert authenticator.modify_auth_state_hook is auth_state_hook

    handled_user_model = user_model("user1")
    handler = generic_client.handler_for_user(handled_user_model)
    data = {"testing": "data"}
    auth_model = await authenticator.authenticate(handler, data)
    if auth_state_hook is sync_auth_state_hook:
        assert auth_model["auth_state"]["sync"]
    else:
        assert auth_model["auth_state"]["async"]
    assert sorted(auth_model["groups"]) == ["alpha", "beta", "user1"]


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
    ["auth_state_groups_key", "expected_error"],
    [
        (
            "oauth_user.permissions.invalid_values_type",
            "The value of the auth_state_groups_key oauth_user.permissions.invalid_values_type is invalid:",
        ),
        (
            "oauth_user.nonexistent.groups",
            "The auth_state_groups_key oauth_user.nonexistent.groups does not exist in the auth_model.",
        ),
    ],
)
async def test_generic_auth_state_groups_key_invalid(
    get_authenticator, generic_client, auth_state_groups_key, expected_error, caplog
):
    caplog.set_level(logging.ERROR)
    c = Config()
    c.GenericOAuthenticator.auth_state_groups_key = auth_state_groups_key
    c.GenericOAuthenticator.admin_groups = ["super_user"]
    c.GenericOAuthenticator.manage_groups = True
    authenticator = get_authenticator(config=c)

    handled_user_model = user_model(
        "user1", permissions={"invalid_values_type": [{"not": {"a": "string"}}]}
    )
    handler = generic_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    assert not auth_model
    assert expected_error in caplog.text


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


class MockUser:
    """Mock subset of JupyterHub User API from the `auth_model` dict"""

    name: str

    def __init__(self, auth_model):
        self._auth_model = auth_model
        self.name = auth_model["name"]

    async def get_auth_state(self):
        return self._auth_model["auth_state"]


@mark.parametrize("enable_refresh_tokens", [True, False])
async def test_refresh_user(get_authenticator, generic_client, enable_refresh_tokens):
    generic_client.enable_refresh_tokens = enable_refresh_tokens
    authenticator = get_authenticator(allowed_users={"user1"})
    authenticator.manage_groups = True
    authenticator.auth_state_groups_key = "oauth_user.groups"
    oauth_userinfo = user_model("user1", groups=["round1"])
    handler = generic_client.handler_for_user(oauth_userinfo)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    auth_state = auth_model["auth_state"]
    assert auth_model["groups"] == ["round1"]
    if enable_refresh_tokens:
        assert "refresh_token" in auth_state
        assert "refresh_token" in auth_state["token_response"]
        assert (
            auth_state["refresh_token"] == auth_state["token_response"]["refresh_token"]
        )
    else:
        assert "refresh_token" not in auth_state["token_response"]
        assert auth_state.get("refresh_token") is None
    user = MockUser(auth_model)
    # case: auth_state not enabled, nothing to refresh
    refreshed = await authenticator.refresh_user(user, handler)
    assert refreshed is True

    # from here on, enable auth state required for refresh to do anything
    authenticator.enable_auth_state = True

    # case: custom refresh hook
    async def async_hook(authenticator, user, auth_state):
        return True

    authenticator.refresh_user_hook = async_hook
    refreshed = await authenticator.refresh_user(user, handler)
    assert refreshed is True

    def sync_hook(authenticator, user, auth_state):
        return False

    authenticator.refresh_user_hook = sync_hook
    refreshed = await authenticator.refresh_user(user, handler)
    assert refreshed is False
    authenticator.refresh_user_hook = None

    # case: no auth state, but auth state enabled needs refresh
    auth_without_state = auth_model.copy()
    auth_without_state["auth_state"] = None
    user_without_state = MockUser(auth_without_state)
    refreshed = await authenticator.refresh_user(user_without_state, handler)
    assert refreshed is False

    # case: actually refresh
    oauth_userinfo["groups"] = ["refreshed"]
    refreshed = await authenticator.refresh_user(user, handler)
    assert refreshed
    assert refreshed["name"] == auth_model["name"]
    assert refreshed["groups"] == ["refreshed"]
    refreshed_state = refreshed["auth_state"]
    assert "access_token" in refreshed_state
    # refresh with access token succeeds, keeps tokens unchanged
    assert refreshed_state.get("refresh_token") == auth_state.get("refresh_token")
    assert refreshed_state["access_token"] == auth_state["access_token"]

    # case: access token is no longer valid, triggers refresh
    oauth_userinfo["groups"] = ["token_refreshed"]
    generic_client.access_tokens.pop(refreshed_state["access_token"])
    refreshed = await authenticator.refresh_user(user, handler)
    if enable_refresh_tokens:
        # access_token refreshed
        assert refreshed
        refreshed_state = refreshed["auth_state"]
        assert (
            refreshed_state["access_token"] != auth_model["auth_state"]["access_token"]
        )
        assert refreshed["groups"] == ["token_refreshed"]
    else:
        assert refreshed is False

    if enable_refresh_tokens:
        # case: token used for refresh is no longer valid
        user = MockUser(refreshed)
        generic_client.access_tokens.pop(refreshed_state["access_token"])
        generic_client.refresh_tokens.pop(refreshed_state["refresh_token"])
        refreshed = await authenticator.refresh_user(user, handler)
        assert refreshed is False


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "claim_groups_key",
            {"claim_groups_key": "groups", "manage_groups": True},
            {"auth_state_groups_key": "oauth_user.groups"},
            logging.WARNING,
            "GenericOAuthenticator.claim_groups_key is deprecated since OAuthenticator 17.0, use GenericOAuthenticator.auth_state_groups_key instead",
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
    c.GenericOAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            GenericOAuthenticator(config=c, log=test_logger)
    else:
        authenticator = GenericOAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples
