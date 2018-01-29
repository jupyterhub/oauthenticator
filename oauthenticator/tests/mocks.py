"""Mocking utilities for testing"""

from io import BytesIO
import json
import os
import re
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qs
import uuid

import pytest

from tornado import gen
from tornado.httpclient import HTTPResponse
from tornado.httputil import HTTPServerRequest
from tornado.log import app_log
from tornado.simple_httpclient import SimpleAsyncHTTPClient
from tornado import web

RegExpType = type(re.compile('.'))


class MockAsyncHTTPClient(SimpleAsyncHTTPClient):
    """A mock AsyncHTTPClient that allows registering handlers for mocked requests
    
    Call .add_host to mock requests made to a given host.
    
    """
    def initialize(self, *args, **kwargs):
        super().initialize(*args, **kwargs)
        self.hosts = {}

    def add_host(self, host, paths):
        """Add a host whose requests should be mocked.
        
        Args:
            host (str): the host to mock (e.g. 'api.github.com')
            paths (list(str|regex, callable)): a list of paths (or regexps for paths)
                and callables to be called for those paths.
                The mock handlers will receive the request as their only argument.
        
        Mock handlers can return:
            - None
            - int (empty response with this status code)
            - str, bytes for raw response content (status=200)
            - list, dict for JSON response (status=200)
            - HTTPResponse (passed unmodified)

        Example::
        
            client.add_host('api.github.com', [
                ('/user': lambda request: {'login': 'name'})
            ])
        """
        self.hosts[host] = paths

    def fetch_impl(self, request, response_callback):
        urlinfo = urlparse(request.url)
        host = urlinfo.hostname
        if host not in self.hosts:
            app_log.warning("Not mocking request to %s", request.url)
            return super().fetch_impl(request, response_callback)
        paths = self.hosts[host]
        response = None
        for path_spec, handler in paths:
            if isinstance(path_spec, str):
                if path_spec == urlinfo.path:
                    response = handler(request)
                    break
            else:
                if path_spec.match(urlinfo.path):
                    response = handler(request)
                    break

        if response is None:
            response = HTTPResponse(request=request, code=404, reason=request.url)
        elif isinstance(response, int):
            response = HTTPResponse(request=request, code=response)
        elif isinstance(response, bytes):
            response = HTTPResponse(request=request, code=200,
                buffer=BytesIO(response),
            )
        elif isinstance(response, str):
            response = HTTPResponse(request=request, code=200,
                buffer=BytesIO(response.encode('utf8')),
            )
        elif isinstance(response, (dict, list)):
            response = HTTPResponse(request=request, code=200,
                buffer=BytesIO(json.dumps(response).encode('utf8')),
                headers={'Content-Type': 'application/json'},
            )

        response_callback(response)


def setup_oauth_mock(client, host, access_token_path, user_path,
        token_type='Bearer',
        token_request_style='post',
    ):
    """setup the mock client for OAuth
    
    generates and registers two handlers common to OAuthenticators:
    
    - create the access token (POST access_token_path)
    - get the user info (GET user_path)
    
    
    and adds a method for creating a new mock handler to pass to .authenticate():
    
    client.handler_for_user(user)
    
    where user is the user-model to be returned by the user request.
    
    Args:
    
        host (str): the host to mock (e.g. api.github.com)
        access_token_path (str): The path for the access token request (e.g. /access_token)
        user_path (str): The path for requesting  (e.g. /user)
        token_type (str): the token_type field for the provider
    """

    client.oauth_codes = oauth_codes = {}
    client.access_tokens = access_tokens = {}

    def access_token(request):
        """Handler for access token endpoint

        Checks code and allocates a new token.
        Replies with JSON model for the token.
        """
        assert request.method == 'POST'
        if token_request_style == 'json':
            body = request.body.decode('utf8')
            try:
                body = json.loads(body)
            except ValueError:
                return HTTPResponse(request=request, code=400,
                    reason="Body not JSON: %r" % body,
                )
            else:
                code = body['code']
        else:
            query = urlparse(request.url).query
            if not query:
                query = request.body.decode('utf8')
            query = parse_qs(query)
            if 'code' not in query:
                return HTTPResponse(request=request, code=400,
                    reason="No code in access token request: url=%s, body=%s" % (
                        request.url, request.body,
                    )
                )
            code = query['code'][0]
        if code not in oauth_codes:
            return HTTPResponse(request=request, code=403,
                reason="No such code: %s" % code,
            )

        # consume code, allocate token
        token = uuid.uuid4().hex
        user = oauth_codes.pop(code)
        access_tokens[token] = user
        return {
            'access_token': token,
            'token_type': token_type,
        }

    def get_user(request):
        assert request.method == 'GET'
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(None, 1)[1]
        else:
            query = parse_qs(urlparse(request.url).query)
            if 'access_token' in query:
                token = query['access_token'][0]
            else:
                return HTTPResponse(request=request, code=403,
                    reason='Missing Authorization header',
                )
        if token not in access_tokens:
            return HTTPResponse(request=request, code=403,
                reason='No such access token: %r' % token,
            )
        return access_tokens.get(token)

    if isinstance(host, str):
        hosts = [host]
    else:
        hosts = host
    for host in hosts:
        client.add_host(host, [
            (access_token_path, access_token),
            (user_path, get_user),
        ])
    
    def handler_for_user(user):
        """Return a new mock RequestHandler
        
        user should be the JSONable model that will ultimately be returned
        from the get_user request.
        """
        code = uuid.uuid4().hex
        oauth_codes[code] = user
        handler = Mock(spec=web.RequestHandler)
        handler.get_argument = Mock(return_value=code)
        handler.request = HTTPServerRequest(
            method='GET',
            uri='https://hub.example.com?code=%s' % code
        )
        handler.hub = Mock(server=Mock(base_url='/hub/'), base_url='/hub/')
        return handler

    client.handler_for_user = handler_for_user


def mock_handler(Handler, uri='https://hub.example.com', method='GET', **settings):
    """Instantiate a Handler in a mock application"""
    application = web.Application(
        hub=Mock(
            base_url='/hub/',
            server=Mock(
                base_url='/hub/'
            ),
        ),
        cookie_secret=os.urandom(32),
        db=Mock(
            rollback=Mock(return_value=None)
        ),
        **settings
    )
    request = HTTPServerRequest(
        method=method,
        uri=uri,
        connection=Mock(),
    )
    handler = Handler(
        application=application,
        request=request,
    )
    handler._transforms = []
    return handler

@gen.coroutine
def no_code_test(authenticator):
    """Run a test to exercise no code in the request"""
    handler = Mock(spec=web.RequestHandler)
    handler.get_argument = Mock(return_value=None)
    with pytest.raises(web.HTTPError) as exc:
        name = yield authenticator.authenticate(handler)
    assert exc.value.status_code == 400
    