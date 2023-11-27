import json
import logging

from jsonschema.exceptions import ValidationError
from pytest import fixture, mark, raises
from traitlets.config import Config
from traitlets.traitlets import TraitError

from ..cilogon import CILogonOAuthenticator, _get_select_idp_param
from .mocks import setup_oauth_mock


@fixture
def cilogon_client(client):
    setup_oauth_mock(
        client,
        host='cilogon.org',
        access_token_path='/oauth2/token',
        user_path='/oauth2/userinfo',
        token_type='token',
    )
    return client


def user_model(username, username_claim, **kwargs):
    """Return a user model with alternate claim name"""
    return {
        username_claim: username,
        "idp": "https://some-idp.com/login/oauth/authorize",
        **kwargs,
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
    ],
)
async def test_cilogon(
    cilogon_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.CILogonOAuthenticator = Config(class_config)
    c.CILogonOAuthenticator.allowed_idps = {
        "https://some-idp.com/login/oauth/authorize": {
            "username_derivation": {
                "username_claim": "name",
            },
        },
    }
    authenticator = CILogonOAuthenticator(config=c)

    handled_user_model = user_model("user1", "name")
    handler = cilogon_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "access_token" in auth_state
        assert "token_response" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info == handled_user_model
        assert auth_model["name"] == user_info["name"]
    else:
        assert auth_model == None


@mark.parametrize(
    "test_variation_id,idp_config,class_config,test_user_name,expect_allowed,expect_admin",
    [
        # test of minimal idp specific config
        (
            "1 - not allowed",
            {
                "username_derivation": {
                    "username_claim": "name",
                },
            },
            {},
            "user1",
            False,
            False,
        ),
        # tests of allow_all
        (
            "2 - allowed by allow_all",
            {
                "username_derivation": {
                    "username_claim": "name",
                },
                "allow_all": True,
            },
            {},
            "user1",
            True,
            None,
        ),
        (
            "3 - not allowed by allow_all",
            {
                "username_derivation": {
                    "username_claim": "name",
                },
                "allow_all": True,
            },
            {},
            "user1",
            True,
            None,
        ),
        # tests of allowed_domains
        (
            "4 - allowed by allowed_domains",
            {
                "username_derivation": {
                    "username_claim": "email",
                },
                "allowed_domains": ["ALLOWED-domain.org"],
            },
            {},
            "user1@allowed-domain.org",
            True,
            None,
        ),
        (
            "5 - not allowed by allowed_domains",
            {
                "username_derivation": {
                    "username_claim": "email",
                },
                "allowed_domains": ["allowed-domain.org"],
            },
            {},
            "user1@not-allowed-domain.org",
            False,
            None,
        ),
        (
            "6 - allowed by allowed_domains (domain stripping action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "strip_idp_domain",
                    "domain": "allowed-domain.org",
                },
                "allowed_domains": ["allowed-domain.org"],
            },
            {},
            "user1@allowed-domain.org",
            True,
            None,
        ),
        (
            "7 - not allowed by allowed_domains (domain stripping action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "strip_idp_domain",
                    "domain": "allowed-domain.org",
                },
                "allowed_domains": ["allowed-domain.org"],
            },
            {},
            "user1@not-allowed-domain.org",
            False,
            None,
        ),
        (
            "8 - allowed by allowed_domains (prefix action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "prefix",
                    "prefix": "some-prefix",
                },
                "allowed_domains": ["allowed-domain.org"],
            },
            {},
            "user1@allowed-domain.org",
            True,
            None,
        ),
        (
            "9 - not allowed by allowed_domains (prefix action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "prefix",
                    "prefix": "some-prefix",
                },
                "allowed_domains": ["allowed-domain.org"],
            },
            {},
            "user1@not-allowed-domain.org",
            False,
            None,
        ),
        (
            "A - allowed by allowed_domains via a wildcard",
            {
                "username_derivation": {
                    "username_claim": "email",
                },
                "allowed_domains": ["allowed-domain.org", "*.allowed-domain.org"],
            },
            {},
            "user1@sub.allowed-domain.org",
            True,
            None,
        ),
        (
            "B - allowed by allowed_domains and allowed_domains_claim",
            {
                "username_derivation": {
                    "username_claim": "email",
                },
                "allowed_domains": ["allowed-domain.org", "*.allowed-domain.org"],
                "allowed_domains_claim": "email",
            },
            {},
            "user1@sub.allowed-domain.org",
            True,
            None,
        ),
        # test of allowed_users and admin_users together with
        # username_derivation actions to verify the final usernames is what
        # matters when describing allowed_users and admin_users
        (
            "10 - allowed by allowed_users (domain stripping action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "strip_idp_domain",
                    "domain": "domain.org",
                },
            },
            {
                "allowed_users": ["user1"],
            },
            "user1@domain.org",
            True,
            None,
        ),
        (
            "11 - allowed by admin_users (domain stripping action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "strip_idp_domain",
                    "domain": "domain.org",
                },
            },
            {
                "admin_users": ["user1"],
            },
            "user1@domain.org",
            True,
            True,
        ),
        (
            "12 - allowed by allowed_users (prefix action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "prefix",
                    "prefix": "some-prefix",
                },
            },
            {
                "allowed_users": ["some-prefix:user1@domain.org"],
            },
            "user1@domain.org",
            True,
            None,
        ),
        (
            "13 - allowed by admin_users (prefix action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "prefix",
                    "prefix": "some-prefix",
                },
            },
            {
                "admin_users": ["some-prefix:user1@domain.org"],
            },
            "user1@domain.org",
            True,
            True,
        ),
        (
            "14 - not allowed by allowed_users (domain stripping action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "strip_idp_domain",
                    "domain": "domain.org",
                },
            },
            {
                "allowed_users": ["user1@domain.org"],
            },
            "user1@domain.org",
            False,
            None,
        ),
        (
            "15 - not allowed by admin_users (domain stripping action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "strip_idp_domain",
                    "domain": "domain.org",
                },
            },
            {
                "admin_users": ["user1@domain.org"],
            },
            "user1@domain.org",
            False,
            None,
        ),
        (
            "16 - not allowed by allowed_users (prefix action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "prefix",
                    "prefix": "some-prefix",
                },
            },
            {
                "allowed_users": ["user1@domain.org"],
            },
            "user1@domain.org",
            False,
            None,
        ),
        (
            "17 - not allowed by admin_users (prefix action involved)",
            {
                "username_derivation": {
                    "username_claim": "email",
                    "action": "prefix",
                    "prefix": "some-prefix",
                },
            },
            {
                "admin_users": ["user1@domain.org"],
            },
            "user1@domain.org",
            False,
            None,
        ),
    ],
)
async def test_cilogon_allowed_idps(
    cilogon_client,
    test_variation_id,
    idp_config,
    class_config,
    test_user_name,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.CILogonOAuthenticator = Config(class_config)
    test_idp = "https://some-idp.com/login/oauth/authorize"
    c.CILogonOAuthenticator.allowed_idps = {
        test_idp: idp_config,
    }
    authenticator = CILogonOAuthenticator(config=c)

    username_claim = idp_config["username_derivation"]["username_claim"]
    handled_user_model = user_model(test_user_name, username_claim, idp=test_idp)
    handler = cilogon_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "access_token" in auth_state
        assert "token_response" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info == handled_user_model
    else:
        assert auth_model == None


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "idp_whitelist",
            {"idp_whitelist": ["dummy"]},
            {},
            logging.ERROR,
            "CILogonOAuthenticator.idp_whitelist is deprecated in CILogonOAuthenticator 0.12.0, use CILogonOAuthenticator.allowed_idps instead",
        ),
        (
            "idp",
            {"idp": "dummy"},
            {},
            logging.ERROR,
            "CILogonOAuthenticator.idp is deprecated in CILogonOAuthenticator 15.0.0, use CILogonOAuthenticator.shown_idps instead",
        ),
        (
            "strip_idp_domain",
            {"strip_idp_domain": True},
            {},
            logging.ERROR,
            "CILogonOAuthenticator.strip_idp_domain is deprecated in CILogonOAuthenticator 15.0.0, use CILogonOAuthenticator.allowed_idps instead",
        ),
        (
            "shown_idps",
            {"shown_idps": ["dummy"]},
            {},
            logging.ERROR,
            "CILogonOAuthenticator.shown_idps is deprecated in CILogonOAuthenticator 16.0.0, use CILogonOAuthenticator.allowed_idps instead",
        ),
        (
            "username_claim",
            {"username_claim": "dummy"},
            {},
            logging.ERROR,
            "CILogonOAuthenticator.username_claim is deprecated in CILogonOAuthenticator 16.0.0, use CILogonOAuthenticator.allowed_idps instead",
        ),
        (
            "additional_username_claims",
            {"additional_username_claims": ["dummy"]},
            {},
            logging.ERROR,
            "CILogonOAuthenticator.additional_username_claims is deprecated in CILogonOAuthenticator 16.0.0, use CILogonOAuthenticator.allowed_idps instead",
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
    c.CILogonOAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            CILogonOAuthenticator(config=c, log=test_logger)
    else:
        authenticator = CILogonOAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples


async def test_config_allowed_idps_wrong_type(caplog):
    """
    Test alllowed_idps is a dict
    """
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = ['pink']

    with raises(TraitError):
        CILogonOAuthenticator(config=c)


async def test_config_allowed_idps_required_username_derivation(caplog):
    # Test username_derivation is a required field of allowed_idps
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {},
    }

    with raises(ValidationError, match="'username_derivation' is a required property"):
        CILogonOAuthenticator(config=c)


async def test_config_allowed_idps_invalid_entity_id(caplog):
    """
    Test allowed_idps keys cannot be domains, but only valid CILogon entity ids,
    i.e. only fully formed URLs
    """
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = {
        'uni.edu': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
                'domain': 'uni.edu',
            },
        },
    }
    log = logging.getLogger('testlog')

    with raises(ValueError):
        CILogonOAuthenticator(config=c, log=log)

    log_msgs = caplog.record_tuples
    expected_deprecation_error = (
        log.name,
        logging.ERROR,
        "Trying to allow an auth provider: uni.edu, that doesn't look like a valid CILogon EntityID.",
    )
    assert expected_deprecation_error in log_msgs


async def test_config_allowed_idps_invalid_type(caplog):
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': 'should-be-a-dict'
    }
    with raises(ValidationError, match="'should-be-a-dict' is not of type 'object'"):
        CILogonOAuthenticator(config=c)


async def test_config_allowed_idps_unrecognized_options(caplog):
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {
            'username_derivation': {'a': 1, 'b': 2}
        }
    }
    with raises(ValidationError, match='Additional properties are not allowed'):
        CILogonOAuthenticator(config=c)


async def test_config_allowed_idps_domain_required(caplog):
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
            }
        }
    }
    with raises(ValidationError, match="'domain' is a required property"):
        CILogonOAuthenticator(config=c)


async def test_config_allowed_idps_prefix_required(caplog):
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'prefix',
            }
        }
    }
    with raises(ValidationError, match="'prefix' is a required property"):
        CILogonOAuthenticator(config=c)


async def test_config_scopes_validation():
    """
    Test that required scopes are appended if not configured.
    """
    c = Config()
    c.CILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'prefix',
                'prefix': 'hub',
            }
        }
    }
    c.CILogonOAuthenticator.scope = ['email']
    authenticator = CILogonOAuthenticator(config=c)

    expected_scopes = ['email', 'openid', 'org.cilogon.userinfo']
    assert authenticator.scope == expected_scopes


async def test_allowed_idps_username_derivation_actions(cilogon_client):
    """
    Tests all `allowed_idps[].username_derivation.action` config choices:
    `strip_idp_domain`, `prefix`, and no action specified.
    """
    c = Config()
    c.CILogonOAuthenticator.allow_all = True
    c.CILogonOAuthenticator.allowed_idps = {
        'https://strip-idp-domain.example.com/login/oauth/authorize': {
            'default': True,
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
                'domain': 'domain-to-strip.edu',
            },
        },
        'https://prefix.example.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'nickname',
                'action': 'prefix',
                'prefix': 'some-prefix',
            },
        },
        'https://no-action.example.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'nickname',
            }
        },
    }
    authenticator = CILogonOAuthenticator(config=c)

    # Test strip_idp_domain action, with domain to strip in username
    handler = cilogon_client.handler_for_user(
        user_model(
            'jtkirk@domain-to-strip.edu',
            'email',
            idp='https://strip-idp-domain.example.com/login/oauth/authorize',
        )
    )
    auth_model = await authenticator.get_authenticated_user(handler, None)
    print(json.dumps(auth_model, sort_keys=True, indent=4))
    assert auth_model['name'] == 'jtkirk'

    # Test strip_idp_domain action, without domain to strip in username
    handler = cilogon_client.handler_for_user(
        user_model(
            'jtkirk@not-domain-to-strip.edu',
            'email',
            idp='https://strip-idp-domain.example.com/login/oauth/authorize',
        )
    )
    auth_model = await authenticator.get_authenticated_user(handler, None)
    print(json.dumps(auth_model, sort_keys=True, indent=4))
    assert auth_model['name'] == 'jtkirk@not-domain-to-strip.edu'

    # Test prefix action
    handler = cilogon_client.handler_for_user(
        user_model(
            'jtkirk', 'nickname', idp='https://prefix.example.com/login/oauth/authorize'
        )
    )
    auth_model = await authenticator.get_authenticated_user(handler, None)
    print(json.dumps(auth_model, sort_keys=True, indent=4))
    assert auth_model['name'] == 'some-prefix:jtkirk'

    # Test no action
    handler = cilogon_client.handler_for_user(
        user_model(
            'jtkirk',
            'nickname',
            idp='https://no-action.example.com/login/oauth/authorize',
        )
    )
    auth_model = await authenticator.get_authenticated_user(handler, None)
    print(json.dumps(auth_model, sort_keys=True, indent=4))
    assert auth_model['name'] == 'jtkirk'


@mark.parametrize(
    "test_variation_id,allowed_idps,expected_return_value",
    [
        (
            "default-specified",
            {
                'https://example4.org': {},
                'https://example3.org': {'default': False},
                'https://example2.org': {'default': True},
                'https://example1.org': {},
            },
            "https://example2.org,https://example4.org,https://example3.org,https://example1.org",
        ),
        (
            "no-truthy-default-specified",
            {
                'https://example4.org': {},
                'https://example3.org': {'default': False},
                'https://example2.org': {},
                'https://example1.org': {},
            },
            "https://example4.org,https://example3.org,https://example2.org,https://example1.org",
        ),
        (
            "no-default-specified-pick-first-entry",
            {
                'https://example4.org': {},
                'https://example3.org': {},
                'https://example2.org': {},
                'https://example1.org': {},
            },
            "https://example4.org,https://example3.org,https://example2.org,https://example1.org",
        ),
    ],
)
async def test__get_selected_idp_param(
    test_variation_id, allowed_idps, expected_return_value
):
    assert _get_select_idp_param(allowed_idps) == expected_return_value
