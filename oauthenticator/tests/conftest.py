"""Py.Test fixtures"""

from tornado.httpclient import AsyncHTTPClient
from pytest import fixture

from .mocks import MockAsyncHTTPClient

@fixture
def client(io_loop, request):
    """Return mocked AsyncHTTPClient"""
    before = AsyncHTTPClient.configured_class()
    AsyncHTTPClient.configure(MockAsyncHTTPClient)
    request.addfinalizer(lambda : AsyncHTTPClient.configure(before))
    c = AsyncHTTPClient()
    assert isinstance(c, MockAsyncHTTPClient)
    return c
