from pytest import fixture, mark

from ..openshift import OpenShiftOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'metadata': {
            'name': username,
        }
    }


@fixture
def openshift_client(client):
    setup_oauth_mock(client,
        host=['localhost'],
        access_token_path='/oauth/token',
        user_path='/oapi/v1/users/~',
    )
    return client


@mark.gen_test
def test_openshift(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'openshift_user' in auth_state

