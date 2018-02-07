"""Py.Test fixtures"""

from tornado.httpclient import AsyncHTTPClient
from tornado import ioloop
from pytest import fixture

from .mocks import MockAsyncHTTPClient


@fixture
def io_loop(request):
    """Same as pytest-tornado.io_loop, adapted for tornado 5"""
    io_loop = ioloop.IOLoop()
    io_loop.make_current()

    def _close():
        io_loop.clear_current()
        io_loop.close(all_fds=True)

    request.addfinalizer(_close)
    return io_loop


@fixture
def client(io_loop, request):
    """Return mocked AsyncHTTPClient"""
    before = AsyncHTTPClient.configured_class()
    AsyncHTTPClient.configure(MockAsyncHTTPClient)
    request.addfinalizer(lambda : AsyncHTTPClient.configure(before))
    c = AsyncHTTPClient()
    assert isinstance(c, MockAsyncHTTPClient)
    return c
