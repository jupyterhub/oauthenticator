import hashlib
import json
import logging
import re
from unittest import mock

from pytest import fixture, mark, raises
from traitlets.config import Config

from ..google import GoogleOAuthenticator
from .mocks import setup_oauth_mock


def user_model(email, username="user1", hd=None):
    """Return a user model"""
    model = {
        'sub': hashlib.md5(email.encode()).hexdigest(),
        'email': email,
        'custom': username,
        'verified_email': True,
    }
    if hd:
        model['hd'] = hd
    return model


@fixture
def google_client(client):
    setup_oauth_mock(
        client,
        host=['accounts.google.com', 'www.googleapis.com'],
        access_token_path=re.compile('^(/o/oauth2/token|/oauth2/v4/token)$'),
        user_path='/oauth2/v1/userinfo',
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
        ("06", {"allowed_google_groups": {"example.com": {"group1"}}}, True, None),
        (
            "07",
            {"allowed_google_groups": {"example.com": {"test-user-not-in-group"}}},
            False,
            None,
        ),
        ("08", {"admin_google_groups": {"example.com": {"group1"}}}, True, True),
        (
            "09",
            {"admin_google_groups": {"example.com": {"test-user-not-in-group"}}},
            False,
            False,
        ),
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
                "allowed_google_groups": {"example.com": {"group1"}},
                "admin_google_groups": {"example.com": {"group1"}},
            },
            True,
            True,
        ),
        (
            "13",
            {
                "allowed_google_groups": {"example.com": {"group1"}},
                "admin_google_groups": {"example.com": {"test-user-not-in-group"}},
            },
            True,
            False,
        ),
        (
            "14",
            {
                "allowed_google_groups": {"example.com": {"test-user-not-in-group"}},
                "admin_google_groups": {"example.com": {"group1"}},
            },
            True,
            True,
        ),
        (
            "15",
            {
                "allowed_google_groups": {"example.com": {"test-user-not-in-group"}},
                "admin_google_groups": {"example.com": {"test-user-not-in-group"}},
            },
            False,
            False,
        ),
        (
            "16",
            {
                "admin_users": {"user1"},
                "admin_google_groups": {"example.com": {"group1"}},
            },
            True,
            True,
        ),
        (
            "17",
            {
                "admin_users": {"user1"},
                "admin_google_groups": {"example.com": {"test-user-not-in-group"}},
            },
            True,
            True,
        ),
        (
            "18",
            {
                "admin_users": {"not-test-user"},
                "admin_google_groups": {"example.com": {"group1"}},
            },
            True,
            True,
        ),
        (
            "19",
            {
                "admin_users": {"not-test-user"},
                "admin_google_groups": {"example.com": {"test-user-not-in-group"}},
            },
            False,
            False,
        ),
    ],
)
async def test_google(
    google_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.GoogleOAuthenticator = Config(class_config)
    c.GoogleOAuthenticator.username_claim = "custom"
    authenticator = GoogleOAuthenticator(config=c)

    handled_user_model = user_model("user1@example.com", "user1")
    handler = google_client.handler_for_user(handled_user_model)
    with mock.patch.object(
        authenticator, "_fetch_user_groups", lambda *args: {"group1"}
    ):
        auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "access_token" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert auth_model["name"] == user_info[authenticator.username_claim]
        if authenticator.allowed_google_groups or authenticator.admin_google_groups:
            assert user_info["google_groups"] == ["group1"]
    else:
        assert auth_model == None


@mark.parametrize(
    "test_variation_id,user_email,user_hd,expect_username,expect_allowed,expect_admin",
    [
        ("01", "user1@ok-hd.orG", "ok-hd.org", "user1", True, True),
        ("02", "user2@ok-hd.orG", "ok-hd.org", "user2", True, None),
        ("03", "blocked@ok-hd.org", "ok-hd.org", None, False, None),
        ("04", "user2@ok-hd.org", "", None, False, None),
        ("05", "user1@not-ok.org", "", None, False, None),
        # Test variation 06 below isn't believed to be possible, but since we
        # aren't sure this test clarifies what we expect to happen.
        ("06", "user1@other.org", "ok-hd.org", "user1@other.org", True, None),
    ],
)
async def test_hosted_domain_single_entry(
    google_client,
    test_variation_id,
    user_email,
    user_hd,
    expect_username,
    expect_allowed,
    expect_admin,
):
    """
    Tests that sign in is restricted to the listed domain and that the username
    represents the part before the `@domain.com` as expected when hosted_domain
    contains a single entry.
    """
    c = Config()
    c.GoogleOAuthenticator.hosted_domain = ["ok-hd.org"]
    c.GoogleOAuthenticator.admin_users = {"user1"}
    c.GoogleOAuthenticator.allowed_users = {"user2", "blocked", "user1@other.org"}
    c.GoogleOAuthenticator.blocked_users = {"blocked"}
    authenticator = GoogleOAuthenticator(config=c)

    handled_user_model = user_model(user_email, hd=user_hd)
    handler = google_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    if expect_allowed:
        assert auth_model
        assert auth_model["name"] == expect_username
        assert auth_model["admin"] == expect_admin
    else:
        assert auth_model == None


@mark.parametrize(
    "name, allowed",
    [
        ("allowed", True),
        ("notallowed", False),
    ],
)
async def test_check_allowed_no_auth_state(google_client, name, allowed):
    authenticator = GoogleOAuthenticator(allowed_users={"allowed"})
    # allow check always gets called with no auth model during Hub startup
    # these are previously-allowed users who should pass until subsequent
    # this check is removed in JupyterHub 5
    assert await authenticator.check_allowed(name, None)


@mark.parametrize(
    "test_variation_id,user_email,user_hd,expect_username,expect_allowed",
    [
        ("01", "user1@ok-hd1.orG", "ok-hd1.org", "user1@ok-hd1.org", True),
        ("02", "user2@ok-hd2.orG", "ok-hd2.org", "user2@ok-hd2.org", True),
        ("03", "blocked@ok-hd1.org", "ok-hd1.org", None, False),
        ("04", "user3@ok-hd1.org", "", None, False),
        ("05", "user1@not-ok.org", "", None, False),
        # Test variation 06 below isn't believed to be possible, but since we
        # aren't sure this test clarifies what we expect to happen.
        ("06", "user1@other.org", "ok-hd1.org", "user1@other.org", True),
    ],
)
async def test_hosted_domain_multiple_entries(
    google_client,
    test_variation_id,
    user_email,
    user_hd,
    expect_username,
    expect_allowed,
):
    """
    Tests that sign in is restricted to the listed domains and that the username
    represents the full email as expected when hosted_domain contains multiple
    entries.
    """
    c = Config()
    c.GoogleOAuthenticator.hosted_domain = [
        "ok-hd1.org",
        "ok-hd2.ORG",
    ]
    c.GoogleOAuthenticator.blocked_users = ["blocked@ok-hd1.org"]
    c.GoogleOAuthenticator.allow_all = True
    authenticator = GoogleOAuthenticator(config=c)

    handled_user_model = user_model(user_email, hd=user_hd)
    handler = google_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    if expect_allowed:
        assert auth_model
        assert auth_model["name"] == expect_username
    else:
        assert auth_model == None


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "google_group_whitelist",
            {"google_group_whitelist": {"example.com": {"dummy"}}},
            {"allowed_google_groups": {"example.com": {"dummy"}}},
            logging.WARNING,
            "GoogleOAuthenticator.google_group_whitelist is deprecated in GoogleOAuthenticator 0.12.0, use GoogleOAuthenticator.allowed_google_groups instead",
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
    c.GoogleOAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            GoogleOAuthenticator(config=c, log=test_logger)
    else:
        authenticator = GoogleOAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples
