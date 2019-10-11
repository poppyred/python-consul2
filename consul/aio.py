from __future__ import absolute_import

import asyncio
import sys
import warnings

import aiohttp

from consul import base

__all__ = ['Consul']
PY_341 = sys.version_info >= (3, 4, 1)


class HTTPClient(base.HTTPClient):
    """Asyncio adapter for python consul using aiohttp library"""

    def __init__(self, *args, loop=None, **kwargs):
        super(HTTPClient, self).__init__(*args, **kwargs)
        self._loop = loop or asyncio.get_event_loop()

    async def _request(self, callback, method, uri, data=None):
        connector = aiohttp.TCPConnector(loop=self._loop,
                                         verify_ssl=self.verify)
        async with aiohttp.ClientSession(connector=connector) as session:
            self._session = session
            resp = await session.request(method=method, url=uri, data=data)
            body = await resp.text(encoding='utf-8')
            content = await resp.read()
            if resp.status == 599:
                raise base.Timeout
            r = base.Response(resp.status, resp.headers, body, content)
            await session.close()
            return callback(r)

    # python prior 3.4.1 does not play nice with __del__ method
    if PY_341:  # pragma: no branch
        def __del__(self):
            warnings.warn("Unclosed connector in aio.Consul.HTTPClient",
                          ResourceWarning)
            # if not self._session.closed:
            #     warnings.warn("Unclosed connector in aio.Consul.HTTPClient",
            #                   ResourceWarning)
            # self._session.close()

    async def get(self, callback, path, params=None):
        uri = self.uri(path, params)
        return await self._request(callback, 'GET', uri)

    async def put(self, callback, path, params=None, data=''):
        uri = self.uri(path, params)
        return await self._request(callback, 'PUT', uri, data=data)

    async def delete(self, callback, path, params=None, data=''):
        uri = self.uri(path, params)
        return await self._request(callback, 'DELETE', uri, data=data)

    async def post(self, callback, path, params=None, data=''):
        uri = self.uri(path, params)
        return await self._request(callback, 'POST', uri, data=data)

    # async def close(self):
    #     await self._session.close()


class Consul(base.Consul):

    def __init__(self, *args, loop=None, **kwargs):
        self._loop = loop or asyncio.get_event_loop()
        super().__init__(*args, **kwargs)

    def http_connect(self, host, port, scheme, verify=True, cert=None):
        return HTTPClient(host, port, scheme, loop=self._loop,
                          verify=verify, cert=None)
