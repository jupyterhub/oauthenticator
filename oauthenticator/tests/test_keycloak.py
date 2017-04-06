import os
from unittest.mock import patch

from pytest import fixture, mark

from ..keycloak import KeycloakOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


def user_model(username):
    """Return a user model"""
    return {
        'preferred_username': username,
    }

@fixture
def keycloak_client(client):
    setup_oauth_mock(client,
                     host='localhost',
                     access_token_path='/auth/realms/master/protocol/openid-connect/token',
                     user_path='/auth/realms/master/protocol/openid-connect/userinfo',
                     )
    return client


@mark.gen_test
def test_keycloak(keycloak_client):
    authenticator = KeycloakOAuthenticator()
    handler = keycloak_client.handler_for_user(
        user_model('someone@example.com'))
    name = yield authenticator.authenticate(handler)
    assert name == 'someone@example.com'


@mark.gen_test
def test_no_code(keycloak_client):
    yield no_code_test(KeycloakOAuthenticator())
