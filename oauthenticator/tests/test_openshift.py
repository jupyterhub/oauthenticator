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
        host=['openshift.default.svc.cluster.local'],
        access_token_path='/oauth/token',
        user_path='/apis/user.openshift.io/v1/users/~',
    )
    return client


async def test_openshift(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    authenticator.openshift_auth_api_url = "https://openshift.default.svc.cluster.local"
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'openshift_user' in auth_state

