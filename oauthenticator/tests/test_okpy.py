from pytest import fixture, mark
from traitlets.config import Config

from ..okpy import OkpyOAuthenticator
from .mocks import no_code_test, setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'name': username,
    }


@fixture
def okpy_client(client):
    setup_oauth_mock(
        client,
        host=['okpy.org'],
        access_token_path='/oauth/token',
        user_path='/api/v3/user',
        token_type='Bearer',
    )
    return client


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
    ],
)
async def test_okpy(
    okpy_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.OkpyOAuthenticator = Config(class_config)
    c.OkpyOAuthenticator.username_claim = "name"
    authenticator = OkpyOAuthenticator(config=c)

    handled_user_model = user_model("user1")
    handler = okpy_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert "access_token" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info == handled_user_model
        assert auth_model["name"] == user_info[authenticator.username_claim]
    else:
        assert auth_model == None


async def test_no_code(okpy_client):
    await no_code_test(OkpyOAuthenticator())
