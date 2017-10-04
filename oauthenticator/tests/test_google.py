from unittest.mock import Mock

from pytest import fixture, mark, raises
from tornado.web import Application, HTTPError

from ..google import GoogleOAuthenticator, GoogleOAuthHandler

from .mocks import setup_oauth_mock

def user_model(email):
    """Return a user model"""
    return {
        'email': email,
        'hd': email.split('@')[1],
    }

@fixture
def google_client(client):
    setup_oauth_mock(client,
        host=['accounts.google.com', 'www.googleapis.com'],
        access_token_path='/o/oauth2/token',
        user_path='/oauth2/v1/userinfo',
    )
    original_handler_for_user = client.handler_for_user
    # testing Google is harder because it invokes methods inherited from tornado
    # classes
    def handler_for_user(user):
        mock_handler = original_handler_for_user(user)
        mock_handler.request.connection = Mock()
        real_handler = GoogleOAuthHandler(
            application=Application(hub=mock_handler.hub),
            request=mock_handler.request,
        )
        return real_handler
    client.handler_for_user = handler_for_user
    return client


@mark.gen_test
def test_google(google_client):
    authenticator = GoogleOAuthenticator()
    handler = google_client.handler_for_user(user_model('fake@email.com'))
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'fake@email.com'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'google_user' in auth_state



@mark.gen_test
def test_hosted_domain(google_client):
    authenticator = GoogleOAuthenticator(hosted_domain='email.com')
    handler = google_client.handler_for_user(user_model('fake@email.com'))#, authenticator)
    user_info = yield authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'fake'

    handler = google_client.handler_for_user(user_model('notallowed@notemail.com'))
    with raises(HTTPError) as exc:
        name = yield authenticator.authenticate(handler)
    assert exc.value.status_code == 403


