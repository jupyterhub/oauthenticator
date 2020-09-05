import json

import logging
from pytest import fixture, mark, raises
from tornado.web import HTTPError
from traitlets.config import Config

from ..cilogon import CILogonOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'eppn': username + '@serenity.space',
    }


def alternative_user_model(username, claimname):
    """Return a user model with alternate claim name"""
    return {
        claimname: username,
    }


@fixture
def cilogon_client(client):
    setup_oauth_mock(client,
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
        alternative_user_model('jtkirk@ufp.gov', 'uid'))
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk@ufp.gov'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': alternative_user_model('jtkirk@ufp.gov',
                                               'uid'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_additional_claim(cilogon_client):
    authenticator = CILogonOAuthenticator(additional_username_claims=['uid'])
    handler = cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid'))
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk@ufp.gov'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': alternative_user_model('jtkirk@ufp.gov',
                                               'uid'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_missing_alternate_claim(cilogon_client):
    authenticator = CILogonOAuthenticator()
    handler = cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid'))
    with raises(HTTPError):
        user_info = await authenticator.authenticate(handler)


def test_deprecated_config(caplog):
    cfg = Config()
    cfg.CILogonOAuthenticator.idp_whitelist = ['pink']

    log = logging.getLogger("testlog")
    authenticator = CILogonOAuthenticator(config=cfg, log=log)
    assert caplog.record_tuples == [
        (
            log.name,
            logging.WARNING,
            'CILogonOAuthenticator.idp_whitelist is deprecated in CILogonOAuthenticator 0.12.0, use '
            'CILogonOAuthenticator.allowed_idps instead',
        )
    ]

    assert authenticator.allowed_idps == ['pink']
