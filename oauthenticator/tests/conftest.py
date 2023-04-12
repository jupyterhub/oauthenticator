"""Py.Test fixtures"""
from pytest import fixture
from tornado.httpclient import AsyncHTTPClient

from .mocks import MockAsyncHTTPClient


@fixture
def client(request):
    """Return mocked AsyncHTTPClient"""
    before = AsyncHTTPClient.configured_class()
    AsyncHTTPClient.configure(MockAsyncHTTPClient)
    request.addfinalizer(lambda: AsyncHTTPClient.configure(before))
    c = AsyncHTTPClient()
    assert isinstance(c, MockAsyncHTTPClient)
    return c
