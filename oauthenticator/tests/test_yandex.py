from pytest import fixture, mark

from ..yandex import YandexPassportOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'email': 'platon@yandex',
        'id': 777,
        'login': username,
        'name': 'Platon Shchukhin',
    }


@fixture
def yandex_client(client):
    setup_oauth_mock(
        client,
        host=['oauth.yandex.ru', 'login.yandex.ru'],
        access_token_path='/token',
        user_path='/info',
        token_type='token',
    )
    return client


@mark.gen_test
def test_yandex(yandex_client):
    authenticator = YandexPassportOAuthenticator()
    handler = yandex_client.handler_for_user(user_model('kidig'))
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'kidig'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'yandex_user' in auth_state
