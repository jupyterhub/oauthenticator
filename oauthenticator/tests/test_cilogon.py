import json
import logging

from pytest import fixture, raises
from tornado.web import HTTPError
from traitlets.config import Config
from traitlets.traitlets import TraitError

from ..cilogon import CILogonOAuthenticator
from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'eppn': username + '@serenity.space',
    }


def alternative_user_model(username, claimname, **kwargs):
    """Return a user model with alternate claim name"""
    return {claimname: username, **kwargs}


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


async def test_cilogon(cilogon_client):
    authenticator = CILogonOAuthenticator()
    handler = cilogon_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'wash@serenity.space'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': user_model('wash'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_alternate_claim(cilogon_client):
    authenticator = CILogonOAuthenticator(username_claim='uid')
    handler = cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid')
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk@ufp.gov'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': alternative_user_model('jtkirk@ufp.gov', 'uid'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_additional_claim(cilogon_client):
    authenticator = CILogonOAuthenticator(additional_username_claims=['uid'])
    handler = cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid')
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk@ufp.gov'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': alternative_user_model('jtkirk@ufp.gov', 'uid'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_missing_alternate_claim(cilogon_client):
    authenticator = CILogonOAuthenticator()
    handler = cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid')
    )
    with raises(HTTPError):
        user_info = await authenticator.authenticate(handler)


def test_deprecated_config(caplog):
    cfg = Config()
    cfg.CILogonOAuthenticator.idp_whitelist = ['pink']

    log = logging.getLogger("testlog")
    CILogonOAuthenticator(config=cfg, log=log)
    log_msgs = caplog.record_tuples

    expected_deprecation_error = (
        log.name,
        logging.WARNING,
        'CILogonOAuthenticator.idp_whitelist is deprecated in CILogonOAuthenticator 0.12.0, use '
        'CILogonOAuthenticator.allowed_idps instead',
    )

    assert expected_deprecation_error in log_msgs


def test_allowed_idps_wrong_type(caplog):
    cfg = Config()
    cfg.CILogonOAuthenticator.allowed_idps = ['pink']

    with raises(TraitError):
        CILogonOAuthenticator(config=cfg)


async def test_allowed_idps_invalid_config_option(caplog):
    cfg = Config()
    # Test config option not recognized
    cfg.CILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': "invalid"
    }

    log = logging.getLogger("testlog")
    authenticator = CILogonOAuthenticator(config=cfg, log=log)
    assert authenticator.allowed_idps == {
        'https://github.com/login/oauth/authorize': {}
    }
    log_msgs = caplog.record_tuples

    expected_deprecation_error = (
        log.name,
        logging.WARNING,
        "The config is not recognized and will be discarded! Available option is https://github.com/login/oauth/authorize.username-derivation.",
    )

    assert expected_deprecation_error in log_msgs


async def test_allowed_idps_invalid_config_type(caplog):
    cfg = Config()
    # Test username-derivation not dict
    cfg.CILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': "username-derivation"
    }

    log = logging.getLogger("testlog")
    authenticator = CILogonOAuthenticator(config=cfg, log=log)
    assert authenticator.allowed_idps == {
        'https://github.com/login/oauth/authorize': {}
    }
    log_msgs = caplog.record_tuples

    expected_deprecation_error = (
        log.name,
        logging.WARNING,
        "The config is not recognized and will be discarded! Available option is https://github.com/login/oauth/authorize.username-derivation.",
    )

    assert expected_deprecation_error in log_msgs


async def test_allowed_idps_invalid_config_username_derivation_options(caplog):
    cfg = Config()
    # Test username-derivation not dict
    cfg.CILogonOAuthenticator.allowed_idps = {
        "https://github.com/login/oauth/authorize": {
            "username-derivation": {"a": 1, "b": 2}
        }
    }

    log = logging.getLogger("testlog")
    authenticator = CILogonOAuthenticator(config=cfg, log=log)
    assert authenticator.allowed_idps == {
        'https://github.com/login/oauth/authorize': {}
    }
    log_msgs = caplog.record_tuples

    expected_deprecation_error = (
        log.name,
        logging.WARNING,
        "Config username-derivation.a not recognized! Available options are: ['username-claim', 'action', 'domain', 'prefix']",
    )
    assert expected_deprecation_error in log_msgs


async def test_allowed_idps_invalid_config_username_domain_stripping(caplog):
    cfg = Config()
    # Test username-derivation not dict
    cfg.CILogonOAuthenticator.allowed_idps = {
        "https://github.com/login/oauth/authorize": {
            "username-derivation": {
                "action": "strip-idp-domain",
            }
        }
    }

    log = logging.getLogger("testlog")
    authenticator = CILogonOAuthenticator(config=cfg, log=log)
    assert authenticator.allowed_idps == {
        'https://github.com/login/oauth/authorize': {}
    }
    log_msgs = caplog.record_tuples

    expected_deprecation_error = (
        log.name,
        logging.WARNING,
        "No domain was specified for stripping. The configuration will be discarded.",
    )
    assert expected_deprecation_error in log_msgs


async def test_allowed_idps_invalid_config_username_prefix(caplog):
    cfg = Config()
    # Test username-derivation not dict
    cfg.CILogonOAuthenticator.allowed_idps = {
        "https://github.com/login/oauth/authorize": {
            "username-derivation": {
                "action": "prefix",
            }
        }
    }

    log = logging.getLogger("testlog")
    authenticator = CILogonOAuthenticator(config=cfg, log=log)
    assert authenticator.allowed_idps == {
        'https://github.com/login/oauth/authorize': {}
    }
    log_msgs = caplog.record_tuples

    expected_deprecation_error = (
        log.name,
        logging.WARNING,
        "No prefix was specified to append. The configuration will be discarded.",
    )
    assert expected_deprecation_error in log_msgs


async def test_cilogon_scopes():
    cfg = Config()
    cfg.CILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {}
    }
    cfg.CILogonOAuthenticator.scope = ['email']

    authenticator = CILogonOAuthenticator(config=cfg)
    expected_scopes = ['email', 'openid', 'org.cilogon.userinfo']

    assert authenticator.scope == expected_scopes


async def test_allowed_auth_providers_validity():
    cfg = Config()
    cfg.CILogonOAuthenticator.allowed_idps = {'uni.edu': {}}

    with raises(ValueError):
        CILogonOAuthenticator(config=cfg)


async def test_strip_and_prefix_username(cilogon_client):
    cfg = Config()
    cfg.CILogonOAuthenticator.allowed_idps = {
        "https://some-idp.com/login/oauth/authorize": {
            "username-derivation": {"action": "strip-idp-domain", "domain": "uni.edu"}
        },
        "https://another-idp.com/login/oauth/authorize": {
            "username-derivation": {
                "username-claim": "nickname",
                "action": "prefix",
                "prefix": "idp",
            }
        },
    }
    cfg.CILogonOAuthenticator.username_claim = 'email'

    authenticator = CILogonOAuthenticator(config=cfg)

    # Test stripping domain
    handler = cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk@uni.edu', 'email', idp="https://some-idp.com/login/oauth/authorize"
        )
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk'

    # Test appending prefixes
    handler = cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk', 'nickname', idp="https://another-idp.com/login/oauth/authorize"
        )
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'idp:jtkirk'
