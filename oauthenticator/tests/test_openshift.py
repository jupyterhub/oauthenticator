import pytest
from traitlets.config import Config

from ..openshift import OpenShiftOAuthenticator
from .mocks import setup_oauth_mock


@pytest.fixture
def openshift_client(client):
    setup_oauth_mock(
        client,
        host=['openshift.default.svc.cluster.local'],
        access_token_path='/oauth/token',
        user_path='/apis/user.openshift.io/v1/users/~',
    )
    return client


def user_model():
    """Return a user model"""
    return {
        "metadata": {"name": "user1"},
        "groups": ["group1"],
    }


@pytest.mark.parametrize(
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
        ("06", {"allowed_groups": {"group1"}}, True, None),
        ("07", {"allowed_groups": {"test-user-not-in-group"}}, False, None),
        ("08", {"admin_groups": {"group1"}}, True, True),
        ("09", {"admin_groups": {"test-user-not-in-group"}}, False, False),
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
                "allowed_users": {"not-test-user"},
                "admin_users": {"user1"},
            },
            True,
            True,
        ),
        (
            "12",
            {
                "allowed_groups": {"group1"},
                "admin_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "13",
            {
                "allowed_groups": {"group1"},
                "admin_groups": {"test-user-not-in-group"},
            },
            True,
            False,
        ),
        (
            "14",
            {
                "allowed_groups": {"test-user-not-in-group"},
                "admin_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "15",
            {
                "allowed_groups": {"test-user-not-in-group"},
                "admin_groups": {"test-user-not-in-group"},
            },
            False,
            False,
        ),
        (
            "16",
            {
                "admin_users": {"user1"},
                "admin_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "17",
            {
                "admin_users": {"user1"},
                "admin_groups": {"test-user-not-in-group"},
            },
            True,
            True,
        ),
        (
            "18",
            {
                "admin_users": {"not-test-user"},
                "admin_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "19",
            {
                "admin_users": {"not-test-user"},
                "admin_groups": {"test-user-not-in-group"},
            },
            False,
            False,
        ),
    ],
)
async def test_openshift(
    openshift_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.OpenShiftOAuthenticator = Config(class_config)
    c.OpenShiftOAuthenticator.openshift_auth_api_url = (
        "https://openshift.default.svc.cluster.local"
    )
    authenticator = OpenShiftOAuthenticator(config=c)

    handled_user_model = user_model()
    handler = openshift_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["name"] == handled_user_model["metadata"]["name"]
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert "access_token" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info == handled_user_model
    else:
        assert auth_model == None
