from pytest import fixture, mark

from ..moodle import MoodleOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'metadata': {
            'name': username,
        }
    }


@fixture
def moodle_client(client):
    setup_oauth_mock(client,
                     host=['localhost'],
                     access_token_path='/oauth/token',
                     user_path='/oauth/user',
                     )
    return client


@mark.gen_test
def test_moodle(moodle_client):
    authenticator = MoodleOAuthenticator()
    handler = moodle_client.handler_for_user(user_model('test.user'))
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'test.user'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'oauth_user' in auth_state
