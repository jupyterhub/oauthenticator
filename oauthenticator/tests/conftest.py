"""Py.Test fixtures"""
import inspect

from pytest import fixture
from tornado.httpclient import AsyncHTTPClient
from tornado.platform.asyncio import AsyncIOMainLoop

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
    request.addfinalizer(lambda: AsyncHTTPClient.configure(before))
    c = AsyncHTTPClient()
    assert isinstance(c, MockAsyncHTTPClient)
    return c


@fixture
def get_auth_model():
    async def mock_auth_model(authenticator, handler):
        access_token_params = authenticator.build_access_tokens_request_params(
            handler, None
        )
        token_info = await authenticator.get_token_info(handler, access_token_params)
        user_info = await authenticator.token_to_user(token_info)
        username = authenticator.user_info_to_username(user_info)
        return {
            "name": username,
            "auth_state": authenticator.build_auth_state_dict(token_info, user_info),
        }

    return mock_auth_model
