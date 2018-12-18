"""Py.Test fixtures"""

import inspect

from tornado.httpclient import AsyncHTTPClient
from tornado import ioloop
from tornado.platform.asyncio import AsyncIOMainLoop
from pytest import fixture

from .mocks import MockAsyncHTTPClient


def pytest_collection_modifyitems(items):
    """add asyncio marker to all async tests"""
    for item in items:
        if inspect.iscoroutinefunction(item.obj):
            item.add_marker('asyncio')


@fixture
def io_loop(event_loop, request):
    """Same as pytest-tornado.io_loop, adapted for tornado 5"""
    io_loop = AsyncIOMainLoop()
    io_loop.make_current()
    assert io_loop.asyncio_loop is event_loop

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
