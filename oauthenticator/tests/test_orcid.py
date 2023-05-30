import functools
import json
import logging
import re
from io import BytesIO
from urllib.parse import parse_qs, urlparse

from pytest import fixture, mark
from tornado.httpclient import HTTPResponse
from tornado.httputil import HTTPHeaders
from traitlets.config import Config

from ..orcid import OrcidOAuthenticator
from .mocks import setup_oauth_mock


def user_model():
    """Return a user model"""
    return {
        'sub': '0000-0002-9079-593X',
        'name': 'Stephen Hawking',
    }


@fixture
def orcid_client(client):
    setup_oauth_mock(
        client,
        host=['orcid.org', 'pub.orcid.org'],
        access_token_path='/oauth/token',
        user_path='/oauth/userinfo',
        token_type='token',
    )
    return client


async def test_orcid(orcid_client):
    authenticator = OrcidOAuthenticator()
    handler = orcid_client.handler_for_user(user_model())
    user_info = await authenticator.authenticate(handler)
    print(user_info)
    name = user_info['name']
    assert name == '0000-0002-9079-593X'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'orcid_user' in auth_state
    assert auth_state["orcid_user"] == {
        'sub': '0000-0002-9079-593X',
        'name': 'Stephen Hawking',
    }
