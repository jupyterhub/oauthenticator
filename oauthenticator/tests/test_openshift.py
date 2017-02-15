from pytest import fixture, mark

from ..openshift import OpenShiftOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


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
    name = yield authenticator.authenticate(handler)
    assert name == 'wash'


@mark.gen_test
def test_no_code(openshift_client):
    yield no_code_test(OpenShiftOAuthenticator())
