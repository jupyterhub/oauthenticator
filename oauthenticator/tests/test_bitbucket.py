import logging

from pytest import fixture, mark, raises
from traitlets.config import Config

from ..bitbucket import BitbucketOAuthenticator
from .mocks import setup_oauth_mock


@fixture
def bitbucket_client(client):
    setup_oauth_mock(
        client,
        host=['bitbucket.org', 'api.bitbucket.org'],
        access_token_path='/site/oauth2/access_token',
        user_path='/2.0/user',
    )

    # mock separate REST API used to check team membership
    team_members = {
        "group1": ["user1"],
    }

    def list_teams(request):
        token = request.headers['Authorization'].split(None, 1)[1]
        username = client.access_tokens[token]['username']
        values = []
        for team, members in team_members.items():
            if username in members:
                values.append({'name': team})
        return {'values': values}

    client.hosts["api.bitbucket.org"].append(('/2.0/workspaces', list_teams))

    return client


def user_model(username):
    """
    Return a user model.

    When passed to handler_for_user, it will populate
    auth_model["auth_state"][authenticator.user_auth_state_key]
    """
    return {
        "username": username,
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
        ("06", {"allowed_teams": {"group1"}}, True, None),
        ("07", {"allowed_teams": {"test-user-not-in-group"}}, False, None),
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
async def test_bitbucket(
    bitbucket_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.BitbucketOAuthenticator = Config(class_config)
    c.BitbucketOAuthenticator.username_claim = "username"
    authenticator = BitbucketOAuthenticator(config=c)

    handled_user_model = user_model("user1")
    handler = bitbucket_client.handler_for_user(handled_user_model)
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


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "whitelist",
            {"whitelist": {"dummy"}},
            {"allowed_users": {"dummy"}},
            logging.WARNING,
            "BitbucketOAuthenticator.whitelist is deprecated in JupyterHub 1.2, use BitbucketOAuthenticator.allowed_users instead",
        ),
        (
            "team_whitelist",
            {"team_whitelist": {"dummy"}},
            {"allowed_teams": {"dummy"}},
            logging.WARNING,
            "BitbucketOAuthenticator.team_whitelist is deprecated in BitbucketOAuthenticator 0.12.0, use BitbucketOAuthenticator.allowed_teams instead",
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
    c.BitbucketOAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            BitbucketOAuthenticator(config=c, log=test_logger)
    else:
        authenticator = BitbucketOAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples
