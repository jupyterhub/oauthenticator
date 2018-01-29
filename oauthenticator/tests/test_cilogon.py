import json

from pytest import fixture, mark

from ..cilogon import CILogonOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'eppn': username + '@serenity.space',
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


@mark.gen_test
def test_cilogon(cilogon_client):
    authenticator = CILogonOAuthenticator()
    handler = cilogon_client.handler_for_user(user_model('wash'))
    user_info = yield authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'wash@serenity.space'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': user_model('wash'),
    }
